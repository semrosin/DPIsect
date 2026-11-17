package runner

import (
	"fmt"
	"strings"
)

// pairedSNISchedule alternates which name goes first in successive pairs.
func pairedSNISchedule(control, treatment string, pairs int) ([]string, error) {
	return pairedSNIScheduleFor(control, treatment, pairs, false)
}

func pairedSNIScheduleFor(control, treatment string, pairs int, allowSame bool) ([]string, error) {
	if control == "" || treatment == "" || (!allowSame && strings.EqualFold(control, treatment)) {
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

func pairedVariant(index int) string {
	if (index/2+index%2)%2 == 0 {
		return "control"
	}
	return "treatment"
}
