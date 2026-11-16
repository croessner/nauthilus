package reputationview

import pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"

const (
	// FieldRole names the subject role field of a published assessment record.
	FieldRole = "role"

	// FieldKind names the subject kind field of a published assessment record.
	FieldKind = "kind"
)

// SubjectAssessment is one decoded published assessment record: the assessed subject and its common tuple.
type SubjectAssessment struct {
	Role  string
	Kind  string
	Tuple Tuple
}

// DecodeSubjectRecord decodes one published assessment record. Fields outside the subject and tuple vocabulary, such
// as catalog correlation fields, are ignored.
func DecodeSubjectRecord(record pluginapi.DecisionRecord) (SubjectAssessment, error) {
	tupleFields := make(map[string]pluginapi.DecisionRecordFieldValue, len(Fields()))
	known := make(map[string]struct{}, len(Fields()))

	for _, field := range Fields() {
		known[field.Name] = struct{}{}
	}

	var assessment SubjectAssessment

	for _, field := range record.Fields() {
		switch name := field.Name(); name {
		case FieldRole:
			assessment.Role, _ = field.Value().Value().StringValue()
		case FieldKind:
			assessment.Kind, _ = field.Value().Value().StringValue()
		default:
			if _, ok := known[name]; ok {
				tupleFields[name] = field.Value()
			}
		}
	}

	if assessment.Role == "" || assessment.Kind == "" {
		return SubjectAssessment{}, ErrAssessment
	}

	tuple, err := Decode(tupleFields)
	if err != nil {
		return SubjectAssessment{}, err
	}

	assessment.Tuple = tuple

	return assessment, nil
}
