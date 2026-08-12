package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/query"
)

// SavedQuery 是一条保存下来的查询。
//
// 存的是"界面上那几个选择",不是编译好的 Query AST。区别在时间范围:
// AST 里的时间必须是绝对区间(否则同一个 AST 在不同时刻含义不同),
// 但保存查询的人想要的恰恰相反 —— 明天打开"可疑的境外 SSH 扫描"这条,
// 要看的是明天的数据,不是保存那一刻的那一小时。
//
// 所以这里存的是 Range 这种相对描述("1h"、"24h"),只有用户明确选了
// 自定义区间时才落绝对时间。
type SavedQuery struct {
	Name string `json:"name"`

	// Range 是时间范围选择器的取值:"15m" / "1h" / ... / "custom"。
	Range string `json:"range"`
	// From/To 仅当 Range 为 "custom" 时有意义,是 datetime-local 的本地时间字符串。
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`

	Metric  string `json:"metric"`
	GroupBy string `json:"group_by"`
	Limit   int    `json:"limit"`

	// Logic 是多个条件之间的关系:AND / OR。
	Logic string `json:"logic"`
	// Filters 是叶子条件列表。界面上的 Query Builder 只能产生这种平铺
	// 结构,所以这里不需要存整棵条件树。
	Filters []query.Condition `json:"filters,omitempty"`

	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// 保存数量与名字长度的上限。
//
// 有上限不是怕磁盘装不下(这些记录一条一百来字节),而是因为这个文件
// 每次写都是整体重写、每次读都全量返回给界面。没有上限的话一个脚本
// 循环调用保存接口就能把它撑到几十 MB,之后每次打开 Explorer 都要传
// 那几十 MB。
const (
	maxSavedQueries = 200
	maxQueryName    = 64
)

// queryStore 是保存查询的持久化。
//
// 用一个 JSON 文件而不是建 ClickHouse 表:这是几十条配置,不是流量数据。
// 放进 ClickHouse 意味着删改要走 ALTER ... DELETE(它的删除是异步的,
// 删完立刻读还可能读到),为了几十条配置去应付那套语义不值得。
type queryStore struct {
	mu   sync.Mutex
	path string
}

func newQueryStore(dataDir string) *queryStore {
	return &queryStore{path: filepath.Join(dataDir, "queries.json")}
}

// load 读全部保存的查询。文件不存在时返回空列表而不是错误 —— 一次都
// 没保存过是正常状态,不该在界面上显示成错误。
func (qs *queryStore) load() ([]SavedQuery, error) {
	b, err := os.ReadFile(qs.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []SavedQuery
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("保存的查询文件 %s 解析失败: %w", qs.path, err)
	}
	return out, nil
}

// save 原子写入:先写临时文件再 rename。
//
// 直接覆盖的话,进程在写一半时被杀会留下一个截断的 JSON,下次启动
// 所有保存的查询一起消失 —— 而用户完全不知道发生了什么。
func (qs *queryStore) save(list []SavedQuery) error {
	if err := os.MkdirAll(filepath.Dir(qs.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := qs.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, qs.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// put 新增或按名字覆盖一条。
func (qs *queryStore) put(q SavedQuery) error {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	list, err := qs.load()
	if err != nil {
		return err
	}
	for i := range list {
		if list[i].Name == q.Name {
			// 同名视为覆盖,但保留最初的创建信息 —— "谁最早建的这条"
			// 比"谁最后按了一次保存"更有用。
			q.CreatedBy, q.CreatedAt = list[i].CreatedBy, list[i].CreatedAt
			list[i] = q
			return qs.save(list)
		}
	}
	if len(list) >= maxSavedQueries {
		return fmt.Errorf("保存的查询已达上限 %d 条,请先删掉一些", maxSavedQueries)
	}
	list = append(list, q)
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return qs.save(list)
}

// del 按名字删除。删一个不存在的名字返回错误,而不是静默成功 ——
// 静默成功会掩盖界面与后端状态不一致(比如两个人同时在删)。
func (qs *queryStore) del(name string) error {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	list, err := qs.load()
	if err != nil {
		return err
	}
	for i := range list {
		if list[i].Name == name {
			list = append(list[:i], list[i+1:]...)
			return qs.save(list)
		}
	}
	return fmt.Errorf("没有名为 %q 的保存查询", name)
}

// validate 校验一条保存查询。
//
// 关键在于复用 query.Query.Validate:字段名、运算符、指标、limit 上限
// 的白名单只有一份。另写一套校验迟早与查询引擎不同步,表现为"能保存
// 但一加载就报不支持",而那时用户已经把条件填完了。
func (sq *SavedQuery) validate() error {
	sq.Name = strings.TrimSpace(sq.Name)
	if sq.Name == "" {
		return fmt.Errorf("请给这条查询起个名字")
	}
	if len([]rune(sq.Name)) > maxQueryName {
		return fmt.Errorf("名字最长 %d 个字", maxQueryName)
	}
	switch sq.Logic {
	case "", "AND":
		sq.Logic = "AND"
	case "OR":
	default:
		return fmt.Errorf("条件关系只能是 AND 或 OR,收到 %q", sq.Logic)
	}
	if sq.Range == "" {
		return fmt.Errorf("缺少时间范围")
	}
	if sq.Range == "custom" && (sq.From == "" || sq.To == "") {
		return fmt.Errorf("自定义时间范围必须同时给出起止时间")
	}

	// 用一个假的时间范围拼出等价的 Query 交给引擎校验。时间范围本身
	// 不在这里查:相对范围是前端解析的,绝对时间要到加载那一刻才成形。
	probe := query.Query{
		TimeRange: query.TimeRange{From: time.Now().Add(-time.Hour), To: time.Now()},
		GroupBy:   []string{sq.GroupBy},
		Metrics:   []string{sq.Metric},
		Limit:     sq.Limit,
		Filters:   sq.condition(),
	}
	if err := probe.Validate(); err != nil {
		return err
	}
	// Validate 会把 Limit 补成默认值,回写以便保存的就是实际生效的值。
	sq.Limit = probe.Limit
	return nil
}

// condition 把平铺的条件列表组装成 AST 的条件树。
func (sq *SavedQuery) condition() query.Condition {
	switch len(sq.Filters) {
	case 0:
		return query.Condition{}
	case 1:
		return sq.Filters[0]
	default:
		return query.Condition{Op: query.Op(sq.Logic), Conditions: sq.Filters}
	}
}

func (s *Server) handleQueriesList(w http.ResponseWriter, r *http.Request, user string) {
	list, err := s.queries.load()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if list == nil {
		list = []SavedQuery{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"queries": list})
}

func (s *Server) handleQuerySave(w http.ResponseWriter, r *http.Request, user string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var sq SavedQuery
	if err := json.NewDecoder(r.Body).Decode(&sq); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误: " + err.Error()})
		return
	}
	if err := sq.validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	sq.CreatedBy, sq.CreatedAt = user, time.Now()
	if err := s.queries.put(sq); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	s.log.Printf("[api] %s 保存了查询 %q", user, sq.Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": sq.Name})
}

func (s *Server) handleQueryDelete(w http.ResponseWriter, r *http.Request, user string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误"})
		return
	}
	if err := s.queries.del(body.Name); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	s.log.Printf("[api] %s 删除了查询 %q", user, body.Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
