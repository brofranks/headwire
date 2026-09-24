package status

import "testing"

func TestValidateField(t *testing.T) {
	for _, field := range append([]string{""}, Fields...) {
		if err := ValidateField(field); err != nil {
			t.Errorf("%q: %v", field, err)
		}
	}
	if ValidateField("bogus") == nil {
		t.Fatal("accepted invalid field")
	}
}
