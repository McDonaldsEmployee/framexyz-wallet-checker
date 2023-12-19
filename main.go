package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fatih/color"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

type Data struct {
	UserInfo UserInfo `json:"userInfo"`
}

type UserInfo struct {
	Address          string  `json:"address"`
	HasClaimedPoints bool    `json:"hasClaimedPoints"`
	TradesMade       int     `json:"tradesMade"`
	VolumeTraded     string  `json:"volumeTraded"`
	RoyaltiesPaid    string  `json:"royaltiesPaid"`
	TopPercent       float64 `json:"topPercent"`
	Rank             int     `json:"rank"`
	TotalAllocation  int     `json:"totalAllocation"`
}

func main() {
	f, err := os.ReadFile("wallets.json")
	if err != nil {
		log.Fatalf("Failed to read file %v", err)
	}

	privateKeys := make([]string, 0)
	err = json.Unmarshal(f, &privateKeys)
	if err != nil {
		log.Fatalf("Failed to unmarshal file %v", err)
	}

	for _, pk := range privateKeys {

		privateKey, err := crypto.HexToECDSA(pk)
		if err != nil {
			log.Fatalf("Failed to retrieve private key %v", err)
		}

		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			log.Fatalf("Failed to assign type to public key%v", err)
		}
		walletAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

		message := "You are claiming the Frame Chapter One Airdrop with the following address: " + strings.ToLower(walletAddress.String())

		signedMessage := signMessage(privateKey, message)

		checkWallet(signedMessage, walletAddress.String())
	}
}

func checkWallet(signature string, publicKey string) {
	url := "https://claim.frame-api.xyz/authenticate"

	payload := strings.NewReader("{\"signature\":\"" + signature + "\",\"address\":\"" + publicKey + "\"}")

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		log.Fatalf("Failed to create request %v", err)
	}

	req.Header.Add("content-type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("Failed to send request %v", err)
	}

	defer res.Body.Close()

	if res.StatusCode == 200 {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			log.Fatalf("Failed to read body %v", err)
		}

		data := &Data{}

		err = json.Unmarshal(body, data)
		if err != nil {
			log.Fatalf("Failed to unmarshall data %v", err)
		}

		userInfo := data.UserInfo

		if userInfo.Rank > 0 {
			if userInfo.HasClaimedPoints {
				color.Green("Wallet: %v | Has Claimed: %v | Allocation: %v | Rank: %v | Top Percent: %f | Volume Traded: %v | Royalties Paid: %v | Trades Made: %v", userInfo.Address, userInfo.HasClaimedPoints, userInfo.TotalAllocation, userInfo.Rank, userInfo.TopPercent, userInfo.VolumeTraded, userInfo.RoyaltiesPaid, userInfo.TradesMade)
			} else {
				color.Blue("Wallet: %v | Has Claimed: %v | Allocation: %v | Rank: %v | Top Percent: %f | Volume Traded: %v | Royalties Paid: %v | Trades Made: %v", userInfo.Address, userInfo.HasClaimedPoints, userInfo.TotalAllocation, userInfo.Rank, userInfo.TopPercent, userInfo.VolumeTraded, userInfo.RoyaltiesPaid, userInfo.TradesMade)
			}
		} else {
			color.Red("Wallet: %v | No Allocation", userInfo.Address)
		}

	}
}

func signMessage(privateKey *ecdsa.PrivateKey, message string) string {
	data := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message))
	hash := crypto.Keccak256Hash(data)

	signatureBytes, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		log.Fatalf("Failed to sign message %v", err)
	}

	signatureBytes[64] += 27

	return hexutil.Encode(signatureBytes)
}
