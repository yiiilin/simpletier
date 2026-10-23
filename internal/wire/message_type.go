package wire

import "fmt"

func validateMessageType(kind FrameKind, messageType MessageType) error {
	switch {
	case kind == FrameKindEndToEnd && messageType >= MessageTypeIPPacket && messageType <= MessageTypeControlRPC:
		return nil
	case kind == FrameKindRouteControl && messageType >= MessageTypeSessionCtrl && messageType <= MessageTypeSessionReady:
		return nil
	default:
		return fmt.Errorf("MessageType 0x%02x invalid for FrameKind 0x%02x: %w", uint8(messageType), uint8(kind), ErrFrameMalformed)
	}
}
