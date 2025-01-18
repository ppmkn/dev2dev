package utils
import (
	"strconv"
	"math/rand"
)

var partOne = []string{
	"Barbarian", "Bard", "Cleric", "Druid", "Fighter", "Warlock",
	"Monk", "Paladin", "Ranger", "Rogue", "Sorcerer", "Wizard",
}


var partTwo = []string{
	"Developer", "Tester", "Analyst", "Designer", "Support",
	"Marketing", "Admin", "Sales", "Writer", "Animator",
	"Modeler", "Artist", "Manager", "Musician", "Engineer",
	"Moderator", "Creator", "Sourcer", "Researcher", "Coder",
}

func GenerateName() string {
	randomOne := rand.Intn(len(partOne))
    randomTwo := rand.Intn(len(partTwo))
	randomNum := rand.Intn(1000)
	numStr := strconv.Itoa(randomNum)

	name := partOne[randomOne] + partTwo[randomTwo] + numStr

	return name
}