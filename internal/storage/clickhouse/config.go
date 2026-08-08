package clickhouse

import "fmt"

// renderServerConfig 生成托管 ClickHouse 子进程的最小 config.xml。
//
// 只绑 127.0.0.1:这是随 ntop2ban 本机跑的内嵌存储,不对外暴露;
// 对外的访问控制由 ntop2ban 自己的 web 层(复用 xdp-ban 的会话/角色)
// 负责,ClickHouse 端口不该被外部直接触达。移除 mysql/postg
// 兼容端口与 interserver 端口(单机内嵌不需要,少开端口少一分面)。
func renderServerConfig(cfg ManagedConfig, logDir, usersPath string) string {
	return fmt.Sprintf(`<clickhouse>
    <logger>
        <level>information</level>
        <log>%s/clickhouse-server.log</log>
        <errorlog>%s/clickhouse-server.err.log</errorlog>
        <size>100M</size>
        <count>3</count>
    </logger>
    <path>%s/</path>
    <tmp_path>%s/tmp/</tmp_path>
    <user_files_path>%s/user_files/</user_files_path>
    <listen_host>127.0.0.1</listen_host>
    <tcp_port>%d</tcp_port>
    <http_port>%d</http_port>
    <users_config>%s</users_config>
    <default_profile>default</default_profile>
    <mark_cache_size>5368709120</mark_cache_size>
</clickhouse>
`, logDir, logDir, cfg.DataDir, cfg.DataDir, cfg.DataDir, cfg.TCPPort, cfg.HTTPPort, usersPath)
}

// usersConfigXML 是托管实例的用户配置。默认用户无密码但只允许本机
// 回环访问——与 renderServerConfig 里只绑 127.0.0.1 一致:内嵌存储的
// 边界防护是"根本连不上",而不是"连上了但要密码"。max_memory_usage
// 给个上限,避免单条失控查询把 ntop2ban 所在主机内存吃光。
const usersConfigXML = `<clickhouse>
    <profiles>
        <default>
            <max_memory_usage>4000000000</max_memory_usage>
        </default>
    </profiles>
    <users>
        <default>
            <password></password>
            <networks>
                <ip>::1</ip>
                <ip>127.0.0.1</ip>
            </networks>
            <profile>default</profile>
            <quota>default</quota>
        </default>
    </users>
    <quotas>
        <default/>
    </quotas>
</clickhouse>
`
