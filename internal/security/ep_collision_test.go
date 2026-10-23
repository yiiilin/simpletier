package security

import "testing"

// 模拟 relay 和 client 在同一进程、同 contextID
func TestSameProcessCollision(t *testing.T) {
	ctx := [32]byte{42}

	// relay 侧作为 responder 接受来自 client 的 epoch
	clientNode := [16]byte{1}
	if err := AcceptLinkEpoch("scope", ctx, clientNode, 0, 1, 1, [32]byte{9}); err != nil {
		t.Fatalf("accept: %v", err)
	}

	// client 侧作为 initiator 申请下一个 epoch
	next, err := NextLinkEpoch("scope", ctx, 0)
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	t.Logf("initiator got epoch %d (relay 也是从 1 开始分配)", next)

	// relay 自己也要作 initiator（它主动连其他节点时）
	relayNext, _ := NextLinkEpoch("scope", ctx, 0)
	t.Logf("relay 作 initiator 时 got epoch %d", relayNext)

	if next == relayNext {
		t.Error("同进程内 initiator 计数器共用了！")
	}
}
