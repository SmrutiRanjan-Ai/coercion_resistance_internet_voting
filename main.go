package zkp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"
	"zkp"
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
	g_0           *generator
	registered    map[string]*voter
	votes         map[string]*encryptedVote
	nonceCounter  int64
	salt          []byte
	bulletinBoard *bulletinBoard
	passCommList  []passCommit
	publicKey     *rsa.PublicKey
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
	ProofPPK *zkp.ChaumPedersenProof
	Status   string
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
	// Parse request body
	var req struct {
		VoterID   string
		Vote      string
		ProofPPK  *zkp.Proof
		EncPubKey []byte
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Lookup voter and validate proof of plaintext knowledge of pk
	voter, ok := ea.registered[req.VoterID]
	if !ok {
		http.Error(w, "voter not registered", http.StatusBadRequest)
		return
	}
	if !zkp.VerifyChaumPedersen(req.ProofPPK, ea.g_0.p, voter.PublicKey, new(big.Int).SetBytes(req.EncPubKey)) {
		http.Error(w, "invalid proof of plaintext knowledge of public key", http.StatusBadRequest)
		return
	}

	// Encrypt vote
	var encryptedVote *encryptedVote
	switch req.Vote {
	case "yes":
		encryptedVote = &encryptedVote{
			PK:     voter.PublicKey,
			Sigma:  nil,
			Proof:  req.ProofPPK,
			Status: "yes",
		}
		if err := encryptedVote.Encrypt(ea.g_0, voter.PassCommitYes); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		voter.EncryptedVoteYes = encryptedVote
	case "no":
		encryptedVote = &encryptedVote{
			PK:     voter.PublicKey,
			Sigma:  nil,
			Proof:  req.ProofPPK,
			Status: "no",
		}
		if err := encryptedVote.Encrypt(ea.g_0, voter.PassCommitNo); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		voter.EncryptedVoteNo = encryptedVote
	default:
		http.Error(w, "invalid vote value", http.StatusBadRequest)
		return
	}

	// Add encrypted vote to the map
	ea.votes[req.VoterID] = encryptedVote

	// Send response
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
