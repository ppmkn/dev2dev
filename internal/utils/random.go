package utils
import (
	"fmt"
	"crypto/rand"
)

func GenerateRandomString(length int) string {
    bytes := make([]byte, length)
    if _, err := rand.Read(bytes); err != nil {
        panic(err)
    }
    return fmt.Sprintf("%x", bytes)
}