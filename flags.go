package mdns

type flags uint16

func (f flags) isQuery() bool {
	if uint16(f>>15) == 0 {
		return true
	}
	return false
}

func (f flags) setIsQuery(isQuery bool) {
}
