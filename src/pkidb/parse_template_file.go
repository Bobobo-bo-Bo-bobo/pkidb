package main

import (
	"encoding/base64"
	"fmt"
	ini "gopkg.in/ini.v1"
	"strings"
)

// ParseTemplateFile - parse template file
func ParseTemplateFile(template string) (*TemplateConfig, error) {
	var config TemplateConfig

	cfg, err := ini.LoadSources(ini.LoadOptions{IgnoreInlineComment: true}, template)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
	}

	sections := cfg.SectionStrings()
	for _, sect := range sections {
		if sect == "DEFAULT" {
			continue
		}

		if sect == "global" {
			global, err := cfg.GetSection("global")
			if err != nil {
				return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
			err = global.MapTo(&config.Global)
			if err != nil {
				return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
			}
		} else if strings.Index(sect, "extension:") == 0 {

			name := strings.Replace(sect, "extension:", "", -1)
			switch strings.ToLower(name) {
			case "keyusage":
				tmplkeyusage := TemplateKeyUsage{}

				s, err := cfg.GetSection(sect)
				if err != nil {
					return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
				}

				err = s.MapTo(&tmplkeyusage)
				if err != nil {
					return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
				}

				keyusage, err := ParseKeyUsageString(tmplkeyusage.Data)
				if err != nil {
					return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
				}

				config.KeyUsage = append(config.KeyUsage, keyusage...)

			case "extendedkeyusage":
				tmplextkeyusage := TemplateExtendedKeyUsage{}

				s, err := cfg.GetSection(sect)
				if err != nil {
					return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
				}

				err = s.MapTo(&tmplextkeyusage)
				if err != nil {
					return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
				}

				extkeyusage, err := ParseExtendedKeyUsageString(tmplextkeyusage.Data)
				if err != nil {
					return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
				}

				config.ExtendedKeyUsage = append(config.ExtendedKeyUsage, extkeyusage...)

			default:
				tmplext := TemplateExtension{}

				s, err := cfg.GetSection(sect)
				if err != nil {
					return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
				}

				err = s.MapTo(&tmplext)
				if err != nil {
					return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
				}
				if tmplext.Data != "" && tmplext.DataBase64 != "" {
					return nil, fmt.Errorf("%s: data and data:base64 are mutually exclusive in a template section", GetFrame())
				}
				extdata := X509ExtensionData{
					Name:     name,
					Critical: tmplext.Critical,
				}

				if tmplext.Data != "" {
					extdata.Data = []byte(tmplext.Data)
				}
				if tmplext.DataBase64 != "" {
					extdata.Data, err = base64.StdEncoding.DecodeString(tmplext.DataBase64)
					if err != nil {
						return nil, fmt.Errorf("%s: %s", GetFrame(), err.Error())
					}
				}

			}
		} else {
			return nil, fmt.Errorf("%s: Invalid template section %s", GetFrame(), sect)
		}
	}

	return &config, nil
}
