package helpers

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
)

var paramRegex *regexp.Regexp = regexp.MustCompile(`^([A-Za-z0-9_]+) \s*(.+)$`)

type SSHDConfigParser struct {
	content        string
	lines          []string
	originalParams []string
	params         map[string]string
}

func ParseSSHDConfigFile(path string) (p *SSHDConfigParser, err error) {

	file, err := os.Open(path)
	if err != nil {
		return
	}

	return ParseSSHDConfig(file)
}

func ParseSSHDConfig(content io.Reader) (p *SSHDConfigParser, err error) {

	p = new(SSHDConfigParser)
	p.params = make(map[string]string)

	// Read content
	contentRaw, err := io.ReadAll(content)
	if err != nil {
		return
	}

	p.content = string(contentRaw)
	p.lines = strings.Split(p.content, "\n")

	for _, line := range p.lines {

		// Ignore comments
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Check if we have a valid sshdconfig parameter line
		params := paramRegex.FindStringSubmatch(line)
		if len(params) != 3 {
			continue
		}

		// Extract infos
		key, value := params[1], params[2]
		p.params[key] = value
		p.originalParams = append(p.originalParams, key)
	}

	return
}

func (p *SSHDConfigParser) GetParam(key string) (value string) {
	return p.params[key]
}

func (p *SSHDConfigParser) SetParam(key, value string) {

	p.params[key] = value
}

func (p *SSHDConfigParser) Dump() (content string) {

	for _, line := range p.lines {

		// Restitute comments as is
		if strings.HasPrefix(line, "#") {
			content += fmt.Sprintf("%s\n", line)
			continue
		}

		// Check if we have a valid sshdconfig parameter line
		// If not, restitute this line as is
		params := paramRegex.FindStringSubmatch(line)
		if len(params) != 3 {
			content += fmt.Sprintf("%s\n", line)
			continue
		}

		// We have a valid param line, checking if the param has been modified
		// since he file was read
		// Extract infos
		key, value := params[1], params[2]

		// We have the param AND it was modified, modifiying line
		if p.params[key] != "" && p.params[key] != value {
			content += fmt.Sprintf("%s %s\n", key, p.params[key])
			continue
		}

		// Param was not modified, keeping the original line
		content += fmt.Sprintf("%s\n", line)
	}

	// We should add at the end the params added by SetParam, but not present in the original file
	extraParamsLine := false
	for key, param := range p.params {

		if !contains(p.originalParams, key) {
			if !extraParamsLine {
				pc, file, line, ok := runtime.Caller(1)
				if ok {
					content += fmt.Sprintf("## ExtraParams added automatically from %s (line #%d, func: %v)\n", file, line, runtime.FuncForPC(pc).Name())
				}
				extraParamsLine = true
			}

			content += fmt.Sprintf("%s %s\n", key, param)
		}
	}

	return
}

func (p *SSHDConfigParser) WriteToFile(path string) (err error) {

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return
	}

	_, err = file.WriteString(p.Dump())
	return
}

// contains checks if a string is present in a slice
func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}
