package hcore

import "testing"

func TestAudit_C1_05_StartWaitsForPreviousCloseCompletion(t *testing.T) {
	t.Skip("C1-05: нужен управляемый тайм-аут Close или точка подмены lifecycle; StartedService имеет конкретный тип, настоящий Box.Close ждёт 10 с, что превышает лимит теста 5 с; менять рабочий код и helper sing-box на этом этапе запрещено")
}
