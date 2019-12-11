package main

// MergeEnvironment - merge environment into configuration
func MergeEnvironment(cfg *PKIConfiguration) error {
	env := GetEnvironment()
	for key, envcfg := range EnvironmentConfigMap {
		envVal, found := env[key]
		if found {
			err := setConfiguration(cfg, envVal, envcfg)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
