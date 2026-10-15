package quic

// onApplicationLimited tells the congestion controller that the connection
// has no more data to send.
func (c *Conn) onApplicationLimited() {
	if appLimited, ok := c.sentPacketHandler.(interface{ OnApplicationLimited() }); ok {
		appLimited.OnApplicationLimited()
	}
}
