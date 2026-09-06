package main

type shadowModelConfig struct {
	Profiles        map[string]profileConfig `mapstructure:"profiles"`
	SourceClassCaps map[string]sourceCap     `mapstructure:"source_class_caps"`
	SignalWeights   map[string]float64       `mapstructure:"signal_weights"`
	ModelID         string                   `mapstructure:"model_id"`
}

// compileShadow admits one separate calibration model without changing source identities or subject attribution.
func (c *configuration) compileShadow() error {
	shadow := c.raw.ShadowModel
	if shadow == nil {
		return nil
	}

	if shadow.ModelID == c.raw.ModelID || len(shadow.SignalWeights) != len(c.raw.Signals) || len(shadow.SourceClassCaps) != len(c.raw.SourceClassCaps) {
		return errConfiguration
	}

	for class := range c.raw.SourceClassCaps {
		if _, exists := shadow.SourceClassCaps[class]; !exists {
			return errConfiguration
		}
	}

	raw := c.raw
	raw.ShadowModel = nil
	raw.ModelID = shadow.ModelID
	raw.Profiles = shadow.Profiles
	raw.SourceClassCaps = shadow.SourceClassCaps

	raw.Signals = make(map[string]signalConfig, len(c.raw.Signals))
	for name, signal := range c.raw.Signals {
		weight, exists := shadow.SignalWeights[name]
		if !exists {
			return errConfiguration
		}

		signal.Weight = weight
		raw.Signals[name] = signal
	}

	compiled, err := compileConfiguration(raw)
	if err != nil {
		return err
	}

	c.shadow = compiled

	return nil
}

// compileModels retains the active model first and adds only the explicitly configured shadow.
func compileModels(cfg *configuration) ([]*modelDefinition, error) {
	active, err := compileModel(cfg)
	if err != nil {
		return nil, err
	}

	models := []*modelDefinition{active}

	if cfg.shadow != nil {
		shadow, err := compileModel(cfg.shadow)
		if err != nil {
			return nil, err
		}

		models = append(models, shadow)
	}

	return models, nil
}
