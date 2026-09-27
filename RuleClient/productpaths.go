package RuleClient

// productPaths 是各产品的内置主动探测路径（key 为指纹文件名）。指纹 YAML 里
// 显式声明 paths 时优先；否则加载时自动注入这里配置的路径。
var productPaths = map[string][]string{
	"weaver.yaml":        {"/wui/index.html", "/wui/theme/ecology"},
	"seeyon.yaml":        {"/seeyon/index.jsp", "/seeyon/"},
	"tongda.yaml":        {"/general/index.php"},
	"springboot.yaml":    {"/actuator/env", "/actuator/health"},
	"tomcat.yaml":        {"/manager/html", "/host-manager/html"},
	"jenkins.yaml":       {"/login", "/api/json"},
	"gitlab.yaml":        {"/users/sign_in"},
	"nacos.yaml":         {"/nacos/", "/v1/console/server/state"},
	"grafana.yaml":       {"/login"},
	"zabbix.yaml":        {"/zabbix/"},
	"phpmyadmin.yaml":    {"/phpmyadmin/"},
	"wordpress.yaml":     {"/wp-login.php"},
	"dedecms.yaml":       {"/plus/"},
	"finereport.yaml":    {"/webroot/decision"},
	"hikvision.yaml":     {"/doc/page/login.asp"},
	"dahua.yaml":         {"/portal/", "/RPC2"},
	"ruijie.yaml":        {"/login.php"},
	"weblogic.yaml":      {"/console/login/LoginForm.jsp"},
	"jboss.yaml":         {"/console/"},
	"confluence.yaml":    {"/login.action"},
	"jira.yaml":          {"/secure/Dashboard.jspa"},
	"exchange.yaml":      {"/owa/"},
	"docker.yaml":        {"/_ping", "/version"},
	"kubernetes.yaml":    {"/api", "/version"},
	"prometheus.yaml":    {"/metrics"},
	"elasticsearch.yaml": {"/_cluster/health"},
	"minio.yaml":         {"/minio/health/live"},
	"solr.yaml":          {"/solr/admin/"},
	"activemq.yaml":      {"/admin/"},
	"nexus.yaml":         {"/service/rest/v1/status"},
	"sonarqube.yaml":     {"/api/system/status"},
	"airflow.yaml":       {"/health"},
	"harbor.yaml":        {"/api/v2.0/health"},
	"yonyou.yaml":        {"/yyoa/"},
	"zentao.yaml":        {"/zentao/"},
}

// productProbes 是各产品的内置主动探测 probes（key 为指纹文件名）：声明了
// probes 的路径使用其独立 matchers 判断，覆盖 paths 的默认复用逻辑。
var productProbes = map[string][]Probe{
	"springboot.yaml": {
		{Path: "/actuator/env", Matchers: []MatcherType{
			{Type: "word", Location: "body", Words: []string{"activeProfiles", "applicationConfig"}},
		}},
		{Path: "/actuator/health", Matchers: []MatcherType{
			{Type: "word", Location: "body", Words: []string{`"status":"UP"`, `"status":"DOWN"`}},
		}},
	},
	"grafana.yaml": {
		{Path: "/api/health", Matchers: []MatcherType{
			{Type: "word", Location: "body", Words: []string{`"database":"ok"`}},
		}},
	},
	"nexus.yaml": {
		{Path: "/service/rest/v1/status", Matchers: []MatcherType{
			{Type: "word", Location: "body", Words: []string{"available"}},
		}},
	},
}
