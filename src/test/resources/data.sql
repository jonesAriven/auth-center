-- 测试数据：管理员账号（密码: admin123）
-- 使用MERGE避免重复插入（多测试类共享H2数据库）
MERGE INTO `user` (username, password, nickname, status) KEY(username) VALUES ('admin', '$2a$10$YfuxV6cAdrN0l1JENSprI.ykW1KD7Ggnul8Ex0V6EbriF92wc/mRK', '管理员', 1);
