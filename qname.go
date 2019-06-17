package mdns

func parseQName(data []byte) (string, error) {
	out := ""
	curLength := 0

	for i := 0; i < len(data); i++ {
		if curLength == 0 {
			curLength = int(data[i])
			continue
		}

		out += string(data[i])
		curLength--

		if curLength == 0 && i != len(data)-1 {
			out += "."
		}
	}

	if curLength != 0 {
		return "", errFailedParsingQName
	}
	return out, nil
}
