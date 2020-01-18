package codes

import (
	"testing"
	"time"
)

func TestCode_MarkAsUsed(t *testing.T) {
	type fields struct {
		ID        string
		Status    Status
		Content   string
		ExpiredAt time.Time
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name:    "can change the state of an enabled token",
			fields:  fields{Status: Enabled},
			wantErr: false,
		},
		{
			name:    "cannot change the state of an enabled not token",
			fields:  fields{Status: Disabled},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Code{
				ID:        tt.fields.ID,
				Status:    tt.fields.Status,
				Content:   tt.fields.Content,
				ExpiredAt: tt.fields.ExpiredAt,
			}
			if err := a.MarkAsUsed(); (err != nil) != tt.wantErr {
				t.Errorf("MarkAsUsed() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
