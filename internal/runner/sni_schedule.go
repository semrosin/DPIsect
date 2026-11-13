package runner

import (
	"fmt"
	"strings"
)

// pairedSNISchedule alternates which name goes first in successive pairs.
func pairedSNISchedule(control, treatment string, pairs int) ([]string, error) {
	if control == "" || treatment == "" || strings.EqualFold(control, treatment) {
		return nil, fmt.Errorf("paired SNI schedule requires two distinct names")
	}
	if pairs < 1 || pairs > int(^uint(0)>>1)/2 {
		return nil, fmt.Errorf("paired SNI schedule: invalid pair count %d", pairs)
	}

	schedule := make([]string, 0, pairs*2)
	for i := 0; i < pairs; i++ {
		if i%2 == 0 {
			schedule = append(schedule, control, treatment)
		} else {
			schedule = append(schedule, treatment, control)
		}
	}
	return schedule, nil
}
