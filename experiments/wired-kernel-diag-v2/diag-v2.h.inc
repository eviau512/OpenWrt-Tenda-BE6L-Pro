/* Inert driver taps. Arm runs in process context without RTNL; root-only
 * control opens CPU observation once. No automatic arming or UNB write.
 */
int be6l_diag_driver_arm(struct airoha_ppe *, const struct bd_config *);
void be6l_diag_driver_command(struct airoha_ppe *, const struct flow_cls_offload *);
void be6l_diag_driver_rx(struct airoha_ppe *, struct sk_buff *, const u32 [20]);
void be6l_diag_driver_stop(struct airoha_ppe *);
void be6l_diag_driver_tx(struct airoha_ppe *, struct sk_buff *, struct net_device *, u32, bool, u8);
void be6l_diag_debugfs_init(struct airoha_ppe *);
