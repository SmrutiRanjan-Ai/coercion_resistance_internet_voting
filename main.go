package zkp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"
)

func main() {
	// Generate an RSA key pair
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	// Initialize the generator g_0 for further computation
	g_0 := initializeGenerator()

	// Create a bulletin board server with a distinct port
	bbPort := ":8081" // Change this to the port you want to use
	bb := newBulletinBoard()
	go startBulletinBoard(bbPort, bb)

	// Create an Election Authority (EA) server with a distinct port
	ea := newElectionAuthority(g_0, bb, &key.PublicKey)
	eaPort := ":8080" // Change this to the port you want to use
	go func() {
		log.Fatal(http.ListenAndServe(eaPort, ea))
	}()

	fmt.Printf("EA server running on port %s\n", eaPort)

	// Wait for the EA server to exit (e.g. by pressing Ctrl+C)
	select {}
}

func initializeGenerator() *generator {
	p, err := generateProbablePrime(1024)
	if err != nil {
		log.Fatal(err)
	}

	q, err := generateProbablePrime(160)
	if err != nil {
		log.Fatal(err)
	}

	g0, err := generateRandomElement(p, q)
	if err != nil {
		log.Fatal(err)
	}

	g := new(generator)
	g.G = g0
	g.P = p
	g.Q = q

	return g
}
func newElectionAuthority(g_0 *generator, bb *bulletinBoard, publicKey *rsa.PublicKey) *electionAuthority {
	ea := &electionAuthority{
		g_0:           g_0,
		registered:    make(map[string]*voter),
		votes:         make(map[string]*encryptedVote),
		nonceCounter:  time.Now().UnixNano(),
		salt:          make([]byte, 32),
		bulletinBoard: bb,
		passCommList:  []passCommit{},
		publicKey:     publicKey,
	}
	if _, err := rand.Read(ea.salt); err != nil {
		panic(err)
	}
	http.HandleFunc("/register", ea.handleRegister)
	http.HandleFunc("/vote", ea.handleVote)
	http.HandleFunc("/verify", ea.handleVerify)
	http.HandleFunc("/count", ea.handleCount)
	return ea
}

type electionAuthority struct {
	g_0              *generator
	registered       map[string]*voter
	votes            map[string]*encryptedVote
	nonceCounter     int64
	salt             []byte
	bulletinBoard    *bulletinBoard
	passCommList     []passCommit
	publicKey        *rsa.PublicKey
	ElectionQuestion []byte
	mutex            sync.Mutex
}

type passCommit struct {
	ID               string
	CommYes          []byte
	CommNo           []byte
	EncryptedCommYes *[]byte
	EncryptedCommNo  *[]byte
	Timestamp        int64
}

type voter struct {
	ID               string
	PublicKey        *rsa.PublicKey
	PassCommitYes    []byte
	PassCommitNo     []byte
	EncryptedVoteYes *encryptedVote
	EncryptedVoteNo  *encryptedVote
	PassCommit       *passCommit
}

type encryptedVote struct {
	PK       []byte
	Sigma    []byte
	Proof    *proof
	Status   string
	ProofPPK *ProofPPK
}

func (ea *electionAuthority) handleRegister(w http.ResponseWriter, r *http.Request) {
	// Parse the JSON request body
	var req struct {
		ID          string         `json:"id"`
		PublicKey   *rsa.PublicKey `json:"public_key"`
		PassCommYes []byte         `json:"pass_comm_yes"`
		PassCommNo  []byte         `json:"pass_comm_no"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Store the voter's details in the registered map
	voterID := req.ID
	if _, ok := ea.registered[voterID]; ok {
		http.Error(w, "voter already registered", http.StatusBadRequest)
		return
	}

	voter := &voter{
		ID:            voterID,
		PublicKey:     req.PublicKey,
		PassCommitYes: req.PassCommYes,
		PassCommitNo:  req.PassCommNo,
		PassCommit: &passCommit{
			ID:        voterID,
			CommYes:   req.PassCommYes,
			CommNo:    req.PassCommNo,
			Timestamp: time.Now().UnixNano(),
		},
	}
	ea.registered[voterID] = voter

	// Send the voter their voter ID and the election authority's public key
	resp := struct {
		ID          string         `json:"id"`
		EAPublicKey *rsa.PublicKey `json:"ea_public_key"`
	}{
		ID:          voterID,
		EAPublicKey: ea.publicKey,
	}

	jsonResp, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send the response to the voter
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResp)
}

func (ea *electionAuthority) handleVote(w http.ResponseWriter, r *http.Request) {
	// Decode the encrypted vote
	var encryptedVote encryptedVote
	err := json.NewDecoder(r.Body).Decode(&encryptedVote)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verify the proof of knowledge of the public key
	pk := new(rsa.PublicKey)
	err = pk.Unmarshal(encryptedVote.PK)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if encryptedVote.ProofPPK == nil {
		http.Error(w, "Missing proof of knowledge of public key", http.StatusBadRequest)
		return
	}
	ok, err := ea.VerifyProofPPK(pk, encryptedVote.ProofPPK)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "Invalid proof of knowledge of public key", http.StatusBadRequest)
		return
	}

	// Verify the signature on the encrypted vote
	ok, err = ea.VerifySignature(encryptedVote.PK, encryptedVote.Sigma, encryptedVote.Status)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "Invalid signature on encrypted vote", http.StatusBadRequest)
		return
	}

	// Decrypt the vote
	vote, err := ea.Decrypt(pk, encryptedVote.Sigma)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Store the vote
	ea.Lock()
	defer ea.Unlock()
	ea.votes = append(ea.votes, vote)

	// Send a confirmation response
	w.WriteHeader(http.StatusOK)
}

func (ea *electionAuthority) handleVerify(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement the /verify endpoint logic here
}

func (ea *electionAuthority) handleCount(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement the /count endpoint logic here
}

func computeGenerator(ea *electionAuthority, numIterations int) []*big.Int {
	base := make([]*big.Int, numIterations)

	g := ea.g_0.G

	for i := 0; i < numIterations; i++ {
		// Choose a random value ai
		ai := getRandomInt()

		// Compute g_i = g^(a_i)
		gi := new(big.Int).Exp(g, ai, ea.g_0.P)

		// Save g_i in the base
		base[i] = gi

		// Prove knowledge of ai with a Schnorr Σ-Protocol
		si, ti, err := proveKnowledgeOfExponent(ai, g, ea.g_0.P, ea.g_0.Q)
		if err != nil {
			log.Fatalf("Error proving knowledge of exponent: %v", err)
		}

		// Store the proof in the generator
		ea.g_0.Si = append(ea.g_0.Si, si)
		ea.g_0.Ti = append(ea.g_0.Ti, ti)
	}

	// Store the base in the generator
	ea.g_0.Base = base

	// Publish the base on the bulletin board
	ea.bulletinBoard.addMessage(fmt.Sprintf("Base: %v", base))

	return base
}

func getRandomInt() *big.Int {
	// Generate a 256-bit random number
	randNum, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil))
	if err != nil {
		panic(err)
	}

	return randNum
}

func proveKnowledgeOfExponent(exp, base, modulus, order *big.Int) (s, t *big.Int, err error) {
	r, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, nil, err
	}

	// Compute challenge c = H(g || h || y || g^r || h^r)
	h := new(big.Int).Exp(base, r, modulus)
	y := new(big.Int).Exp(base, exp, modulus)
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, []*big.Int{base, h, y, new(big.Int).SetBytes(buf.Bytes())})
	if err != nil {
		return nil, nil, err
	}
	c := hash(buf.Bytes())

	// Compute response s = r + c*a mod q, t = c mod q
	s = new(big.Int).Mul(c, exp)
	s.Add(s, r)
	s.Mod(s, order)
	t = new(big.Int).Mod(c, order)

	return s, t, nil
}

func hash(data []byte) *big.Int {
	h := sha256.Sum256(data)
	return new(big.Int).SetBytes(h[:])
}

func publishBase(base []*big.Int) {
	fmt.Println(base)
	// TODO: Implement a function that publishes the base on the bulletin board
}

type generator struct {
	G    *big.Int
	P    *big.Int
	Q    *big.Int
	Si   []*big.Int
	Ti   []*big.Int
	Base []*big.Int
}

func (gen *generator) GeneratePQ(bitSize int) error {
	p, err := rand.Prime(rand.Reader, bitSize)
	if err != nil {
		return err
	}

	// Ensure that P-1 is divisible by Q
	var q *big.Int
	for {
		q, err = rand.Prime(rand.Reader, bitSize/2)
		if err != nil {
			return err
		}
		if p.Sub(p, big.NewInt(1)).Mod(p, q).Int64() == 0 {
			break
		}
	}

	gen.P = p
	gen.Q = q

	return nil
}

func (ea *electionAuthority) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/register":
		ea.handleRegister(w, r)
	case "/cast":
		ea.handleVote(w, r)
	case "/verify":
		ea.handleVerify(w, r)
	case "/count":
		ea.handleCount(w, r)
	default:
		http.NotFound(w, r)
	}
}
func generateProbablePrime(bits int) (*big.Int, error) {
	// Generate a random number with the specified number of bits
	randNum, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	// Test if the number is a probable prime
	if !randNum.ProbablyPrime(20) {
		return generateProbablePrime(bits)
	}

	return randNum, nil
}

func generateRandomElement(p, q *big.Int) (*big.Int, error) {
	max := new(big.Int).Sub(p, big.NewInt(1)) // max = p - 1
	g0, err := rand.Int(rand.Reader, max)     // generate a random number between 0 and max
	if err != nil {
		return nil, err
	}
	g0.Add(g0, big.NewInt(1))                         // g0 = g0 + 1
	g0.Exp(g0, new(big.Int).Mul(q, big.NewInt(2)), p) // g0 = (g0^(2q)) mod p
	return g0, nil
}

type bulletinBoard struct {
	mu     sync.Mutex
	posts  []string
	nextID int
}

func (bb *bulletinBoard) publish(post string) int {
	bb.mu.Lock()
	defer bb.mu.Unlock()
	id := bb.nextID
	bb.nextID++
	bb.posts = append(bb.posts, post)
	return id
}

func (bb *bulletinBoard) retrieveAll() []string {
	bb.mu.Lock()
	defer bb.mu.Unlock()
	return bb.posts
}

func (bb *bulletinBoard) addMessage(msg string) int {
	bb.mu.Lock()
	defer bb.mu.Unlock()
	id := bb.nextID
	bb.nextID++
	bb.posts = append(bb.posts, msg)
	return id
}

func newBulletinBoard() *bulletinBoard {
	return &bulletinBoard{
		nextID: 1,
	}
}

func (bb *bulletinBoard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		posts := bb.retrieveAll()
		enc := json.NewEncoder(w)
		if err := enc.Encode(posts); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case http.MethodPost:
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		id := bb.addMessage(string(body))
		fmt.Fprintf(w, "Posted with ID: %d", id)
	default:
		http.Error(w, "Unsupported method", http.StatusMethodNotAllowed)
	}
}

func startBulletinBoard(port string, bb *bulletinBoard) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			msg := r.FormValue("message")
			if msg != "" {
				bb.addMessage(msg)
			}
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, "<html><body>")
		for _, msg := range bb.retrieveAll() {
			fmt.Fprintf(w, "<div>%s</div>", msg)
		}
		fmt.Fprintln(w, `<form method="POST">
			<label for="message">Message:</label>
			<input type="text" name="message" id="message" />
			<input type="submit" value="Submit" />
		</form>`)
		fmt.Fprintln(w, "</body></html>")
	})

	log.Fatal(http.ListenAndServe(port, nil))
}

func generateRSAKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey, nil
}

func encryptWithPublicKey(pubKey *rsa.PublicKey, message []byte) ([]byte, error) {
	// Generate random padding for OAEP encryption
	randSource := rand.Reader
	label := []byte("")
	hash := crypto.SHA256
	encrypted, err := rsa.EncryptOAEP(hash.New(), randSource, pubKey, message, label)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

type proof struct {
	a *big.Int
	b *big.Int
}

// GenerateProof generates a proof of plaintext knowledge for the given public key and its corresponding plaintext.
// Returns an error if the proof generation fails.
func (ea *electionAuthority) GenerateProof(pubKey *rsa.PublicKey, plaintext *big.Int) (*proof, error) {
	// Generate two random numbers r and s
	r, err := rand.Int(rand.Reader, pubKey.N)
	if err != nil {
		return nil, err
	}
	s, err := rand.Int(rand.Reader, pubKey.N)
	if err != nil {
		return nil, err
	}

	// Compute the challenge value c = H(pubKey || plaintext || r || s)
	h := sha256.New()
	h.Write(pubKey.N.Bytes())
	h.Write(plaintext.Bytes())
	h.Write(r.Bytes())
	h.Write(s.Bytes())
	c := new(big.Int).SetBytes(h.Sum(nil))

	// Compute the responses a = r - cx and b = s - cx
	a := new(big.Int).Sub(r, new(big.Int).Mul(c, plaintext))
	b := new(big.Int).Sub(s, new(big.Int).Mul(c, plaintext))

	// Return the proof
	return &proof{a, b}, nil
}

// VerifyProof verifies the given proof of plaintext knowledge for the given public key and its corresponding plaintext.
// Returns an error if the verification fails.

func VerifyProof(pubKey *rsa.PublicKey, plaintext *big.Int, p *proof) error {
	// Compute the challenge value c = H(pubKey || plaintext || p.a || p.b)
	h := sha256.New()
	h.Write(pubKey.N.Bytes())
	h.Write(plaintext.Bytes())
	h.Write(p.a.Bytes())
	h.Write(p.b.Bytes())
	c := new(big.Int).SetBytes(h.Sum(nil))

	// Compute the values x1 = g^a * y^c and x2 = h^b * g^c
	g := big.NewInt(2)
	y := new(big.Int).Exp(new(big.Int).SetInt64(int64(pubKey.E)), p.a, pubKey.N)
	h1 := sha256.Sum256([]byte("g"))
	h2 := sha256.Sum256([]byte("h"))
	hBytes := sha256.Sum256(append(h1[:], h2[:]...))
	hInt := new(big.Int).SetBytes(hBytes[:])
	x1 := new(big.Int).Exp(g, p.a, pubKey.N)
	x1.Mul(x1, new(big.Int).Exp(y, c, pubKey.N))
	x2 := new(big.Int).Exp(hInt, p.b, pubKey.N)
	x2.Mul(x2, new(big.Int).Exp(g, c, pubKey.N))

	// Compute the final challenge value c' = H(pubKey || plaintext || x1 || x2)
	h.Reset()
	h.Write(pubKey.N.Bytes())
	h.Write(plaintext.Bytes())
	h.Write(x1.Bytes())
	h.Write(x2.Bytes())
	cPrime := new(big.Int).SetBytes(h.Sum(nil))

	// Check if the computed challenge value matches the original challenge value
	if cPrime.Cmp(c) != 0 {
		return errors.New("proof verification failed")
	}

	return nil
}

type ProofPPK struct {
	Z  []byte
	T1 []byte
	T2 []byte
	T3 []byte
	E  []byte
	S  []byte
}

func (ea *electionAuthority) GenerateProofPPK(pk *rsa.PublicKey) (*ProofPPK, error) {
	// Generate a random value r
	r, err := rand.Int(rand.Reader, pk.N)
	if err != nil {
		return nil, err
	}

	// Compute the proof components
	n := pk.N
	g := big.NewInt(2)
	pkInt := new(big.Int).SetBytes(ea.PublicKeyBytes())
	z := new(big.Int).Mod(r, n)
	t1 := new(big.Int).Exp(pkInt, r, n)
	t2 := new(big.Int).Exp(g, z, n)
	t3 := new(big.Int).Mod(new(big.Int).Mul(t1, t2), n)
	hash := sha256.Sum256([]byte(t3.String()))
	e := new(big.Int).SetBytes(hash[:])
	s := new(big.Int).Mod(new(big.Int).Sub(r, new(big.Int).Mul(e, pkInt)), n)

	// Return the proof
	proof := &ProofPPK{
		Z:  z.Bytes(),
		T1: t1.Bytes(),
		T2: t2.Bytes(),
		T3: t3.Bytes(),
		E:  e.Bytes(),
		S:  s.Bytes(),
	}
	return proof, nil
}

func (ea *electionAuthority) VerifyProofPPK(pk *rsa.PublicKey, proof *ProofPPK) (bool, error) {
	// Decompose the public key into its components
	n := pk.N
	g := big.NewInt(2)
	h := new(big.Int).Exp(g, new(big.Int).SetBytes(proof.Z), n)
	t1 := new(big.Int).SetBytes(proof.T1)
	t2 := new(big.Int).Exp(g, new(big.Int).SetBytes(proof.Z), n)
	t3 := new(big.Int).SetBytes(proof.T3)
	h.Mul(h, t1)
	h.Mod(h, n)
	h.Mul(h, t2)
	h.Mod(h, n)

	// Compute e = H(t3)
	hash := sha256.Sum256(proof.T3)
	e := new(big.Int).SetBytes(hash[:])

	// Compute s = r - e * pk
	r1 := new(big.Int).SetBytes(proof.S)
	pkInt := new(big.Int).SetBytes(ea.PublicKeyBytes())
	s := new(big.Int).Mod(new(big.Int).Sub(r1, new(big.Int).Mul(e, pkInt)), n)

	// Verify the proof
	return h.Cmp(t3) == 0 && s.Cmp(r1) == 0, nil
}

func (ea *electionAuthority) PublicKeyBytes() []byte {
	return ea.publicKey.N.Bytes()
}

func (ea *electionAuthority) VerifySignature(encryptedVote *encryptedVote) (bool, error) {
	// Get the public key
	pubKey, err := ea.BytesToPublicKey(encryptedVote.PK)
	if err != nil {
		return false, err
	}

	// Verify the signature
	hashedVote := sha256.Sum256(encryptedVote.Sigma)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashedVote[:], encryptedVote.Sigma)
	if err != nil {
		return false, err
	}

	// Verify the proof of partial knowledge of the private key
	ok, err := ea.VerifyProofPPK(pubKey, encryptedVote.ProofPPK)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, errors.New("invalid proof of partial knowledge of the private key")
	}

	// Everything is valid
	return true, nil
}

func (ea *electionAuthority) BytesToPublicKey(pkBytes []byte) (*rsa.PublicKey, error) {
	var pubKey rsa.PublicKey
	err := json.Unmarshal(pkBytes, &pubKey)
	if err != nil {
		return nil, err
	}
	return &pubKey, nil
}
