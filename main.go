package main

import (
    "context"
    //"encoding/gob"
    "encoding/json"
    "fmt"
    "html/template"
    "io"
    "log"
    "net/http"
    "strings"
    "os"
    "time"

    "github.com/gorilla/sessions"
    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/joho/godotenv"
    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/google"
)

// TemplateRenderer is a custom renderer for Echo
type TemplateRenderer struct {
    templates *template.Template
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
    return t.templates.ExecuteTemplate(w, name, data)
}

// Data structures
type LongTerm struct {
    SocialLife       int `json:"social_life"`
    Academics        int `json:"academics"`
    CoCurriculum     int `json:"co_curriculum"`
    ExtraCurriculum  int `json:"extra_curriculum"`
    Health           int `json:"health"`
    SelfProjects     int `json:"self_projects"`
}

type WeekActual struct {
    SocialLife       int `json:"social_life"`
    Academics        int `json:"academics"`
    CoCurriculum     int `json:"co_curriculum"`
    ExtraCurriculum  int `json:"extra_curriculum"`
    Health           int `json:"health"`
    SelfProjects     int `json:"self_projects"`
}

type Week struct {
    WeekNumber int       `json:"week_number"`
    Actuals    WeekActual `json:"actuals"`
    CreatedAt  time.Time `json:"created_at"`
}

func main() {
    // Load .env
    err := godotenv.Load()
    if err != nil {
        log.Fatal("Error loading .env file")
    }

    // Database connection
    dbPool, err := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
    if err != nil {
        log.Fatal("Unable to connect to database:", err)
    }
    defer dbPool.Close()

    // Session store (using cookies)
    sessionStore := sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
    sessionStore.Options = &sessions.Options{
        Path:     "/",
        MaxAge:   86400 * 7, // 7 days
        HttpOnly: true,
        Secure:   false, // set to true in production with HTTPS
    }

    // Google OAuth config
    oauthConfig := &oauth2.Config{
        ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
        ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
        RedirectURL:  "http://localhost:8080/auth/callback",
        Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
        Endpoint:     google.Endpoint,
    }

    // Echo instance
    e := echo.New()
    e.Use(middleware.Logger())
    e.Use(middleware.Recover())

    /*// Template renderer
    renderer := &TemplateRenderer{
        templates: template.Must(template.ParseGlob("views/*.html")),
    }
    e.Renderer = renderer*/
    // Template renderer with custom functions
    funcMap := template.FuncMap{
        "replace": func(s, old, new string) string {
            return strings.ReplaceAll(s, old, new)
        },
    }
    renderer := &TemplateRenderer{
        templates: template.Must(template.New("").Funcs(funcMap).ParseGlob("views/*.html")),
    }
    e.Renderer = renderer

    // Serve static files (optional, for custom CSS/JS)
    e.Static("/static", "static")

    // Routes
    e.GET("/", func(c echo.Context) error {
        return c.Redirect(http.StatusFound, "/login")
    })

    e.GET("/login", handleLogin(oauthConfig))
    e.GET("/auth/callback", handleAuthCallback(oauthConfig, sessionStore, dbPool))

    // Protected routes (require auth)
    authGroup := e.Group("")
    authGroup.Use(authMiddleware(sessionStore))

    authGroup.GET("/dashboard", handleDashboard(dbPool, sessionStore))
    authGroup.GET("/set-long-term", handleSetLongTerm(dbPool, sessionStore))
    authGroup.POST("/set-long-term", handleSetLongTermPost(dbPool, sessionStore))
    authGroup.GET("/week-entry", handleWeekEntry(dbPool, sessionStore))
    authGroup.POST("/week-entry", handleWeekEntryPost(dbPool, sessionStore))
    authGroup.POST("/logout", handleLogout(sessionStore))

    // Start server
    e.Logger.Fatal(e.Start(":" + os.Getenv("PORT")))
}

// ---------- Helper functions ----------
func getUserID(c echo.Context, store *sessions.CookieStore) (int, error) {
    session, _ := store.Get(c.Request(), "session")
    userID, ok := session.Values["userID"].(int)
    if !ok {
        return 0, fmt.Errorf("not authenticated")
    }
    return userID, nil
}

func toInt(s string) int {
    var i int
    fmt.Sscanf(s, "%d", &i)
    return i
}

func getLongTermValue(lt LongTerm, cat string) int {
    switch cat {
    case "social_life":
        return lt.SocialLife
    case "academics":
        return lt.Academics
    case "co_curriculum":
        return lt.CoCurriculum
    case "extra_curriculum":
        return lt.ExtraCurriculum
    case "health":
        return lt.Health
    case "self_projects":
        return lt.SelfProjects
    }
    return 0
}

// ---------- Authentication handlers ----------
func handleLogin(oauthConfig *oauth2.Config) echo.HandlerFunc {
    return func(c echo.Context) error {
        url := oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
        return c.Redirect(http.StatusTemporaryRedirect, url)
    }
}

func handleAuthCallback(oauthConfig *oauth2.Config, store *sessions.CookieStore, db *pgxpool.Pool) echo.HandlerFunc {
    return func(c echo.Context) error {
        code := c.QueryParam("code")
        token, err := oauthConfig.Exchange(context.Background(), code)
        if err != nil {
            return c.String(http.StatusInternalServerError, "Failed to exchange token")
        }

        // Get user info from Google
        client := oauthConfig.Client(context.Background(), token)
        resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
        if err != nil {
            return c.String(http.StatusInternalServerError, "Failed to get user info")
        }
        defer resp.Body.Close()

        var userInfo struct {
            Email string `json:"email"`
        }
        if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
            return c.String(http.StatusInternalServerError, "Failed to decode user info")
        }

        // Find or create user in database
        var userID int
        err = db.QueryRow(context.Background(),
            "INSERT INTO users (email) VALUES ($1) ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email RETURNING id",
            userInfo.Email).Scan(&userID)
        if err != nil {
            return c.String(http.StatusInternalServerError, "Database error")
        }

        // Store user ID in session
        session, _ := store.Get(c.Request(), "session")
        session.Values["userID"] = userID
        session.Save(c.Request(), c.Response())

        // Check if user has long-term priorities
        var hasPriorities bool
        err = db.QueryRow(context.Background(),
            "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND long_term != '{}'::jsonb)", userID).Scan(&hasPriorities)
        if err != nil {
            return c.String(http.StatusInternalServerError, "Database error")
        }

        /*if !hasPriorities {
            return c.Redirect(http.StatusFound, "/set-long-term")
        }
        return c.Redirect(http.StatusFound, "/dashboard")*/
        log.Println("User ID:", userID)
        log.Println("Has priorities:", hasPriorities)
        if !hasPriorities {
            log.Println("Redirecting to /set-long-term")
            return c.Redirect(http.StatusFound, "/set-long-term")
        }
        log.Println("Redirecting to /dashboard")
        return c.Redirect(http.StatusFound, "/dashboard")
    }
}

func authMiddleware(store *sessions.CookieStore) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            session, _ := store.Get(c.Request(), "session")
            if userID, ok := session.Values["userID"]; !ok || userID == nil {
                return c.Redirect(http.StatusFound, "/login")
            }
            return next(c)
        }
    }
}

func handleLogout(store *sessions.CookieStore) echo.HandlerFunc {
    return func(c echo.Context) error {
        session, _ := store.Get(c.Request(), "session")
        session.Values = make(map[interface{}]interface{})
        session.Save(c.Request(), c.Response())
        return c.Redirect(http.StatusFound, "/login")
    }
}

// ---------- Dashboard handler ----------
func handleDashboard(db *pgxpool.Pool, store *sessions.CookieStore) echo.HandlerFunc {
    return func(c echo.Context) error {
        userID, err := getUserID(c, store)
        if err != nil {
            return c.Redirect(http.StatusFound, "/login")
        }

        // Fetch user's long-term priorities
        var longTerm LongTerm
        err = db.QueryRow(context.Background(),
            "SELECT long_term FROM users WHERE id=$1", userID).Scan(&longTerm)
        if err != nil {
            return c.String(http.StatusInternalServerError, "Database error")
        }

        // Fetch all weeks for this user
        rows, err := db.Query(context.Background(),
            "SELECT week_number, actuals, created_at FROM weeks WHERE user_id=$1 ORDER BY week_number", userID)
        if err != nil {
            return c.String(http.StatusInternalServerError, "Database error")
        }
        defer rows.Close()

        var weeks []Week
        for rows.Next() {
            var w Week
            err = rows.Scan(&w.WeekNumber, &w.Actuals, &w.CreatedAt)
            if err != nil {
                continue
            }
            weeks = append(weeks, w)
        }

        // Determine if user can add a new week
        var canAddWeek bool
        var nextWeekNumber int
        if len(weeks) == 0 {
            canAddWeek = true
            nextWeekNumber = 1
        } else {
            lastWeek := weeks[len(weeks)-1]
            daysSince := time.Since(lastWeek.CreatedAt).Hours() / 24
            canAddWeek = daysSince >= 7
            nextWeekNumber = lastWeek.WeekNumber + 1
        }

        // Calculate cumulative deviation
        cumulativeDev := make(map[string]float64)
        categories := []string{"social_life", "academics", "co_curriculum", "extra_curriculum", "health", "self_projects"}
        sums := make(map[string]int)
        for _, cat := range categories {
            sums[cat] = 0
        }

        for _, w := range weeks {
            sums["social_life"] += w.Actuals.SocialLife
            sums["academics"] += w.Actuals.Academics
            sums["co_curriculum"] += w.Actuals.CoCurriculum
            sums["extra_curriculum"] += w.Actuals.ExtraCurriculum
            sums["health"] += w.Actuals.Health
            sums["self_projects"] += w.Actuals.SelfProjects
        }

        if len(weeks) > 0 {
            for _, cat := range categories {
                avg := float64(sums[cat]) / float64(len(weeks))
                longVal := getLongTermValue(longTerm, cat)
                cumulativeDev[cat] = avg - float64(longVal)
            }
        }

        // Fetch other users' long-term priorities
        rows, err = db.Query(context.Background(),
            "SELECT id, long_term FROM users WHERE id != $1", userID)
        if err != nil {
            return c.String(http.StatusInternalServerError, "Database error")
        }
        defer rows.Close()

        type OtherUser struct {
            ID       int
            LongTerm LongTerm
        }
        var otherUsers []OtherUser
        for rows.Next() {
            var ou OtherUser
            err = rows.Scan(&ou.ID, &ou.LongTerm)
            if err == nil {
                otherUsers = append(otherUsers, ou)
            }
        }

        // Prepare data for template
        data := map[string]interface{}{
            "LongTerm":       longTerm,
            "Weeks":          weeks,
            "CanAddWeek":     canAddWeek,
            "NextWeekNumber": nextWeekNumber,
            "CumulativeDev":  cumulativeDev,
            "OtherUsers":     otherUsers,
            "User":           map[string]interface{}{"ID": userID},
        }

        // If there is at least one week, pass last week data for chart
        if len(weeks) > 0 {
            last := weeks[len(weeks)-1].Actuals
            data["LastWeek"] = last
            data["Labels"] = []string{"Social", "Academics", "Co-curric", "Extra-curric", "Health", "Projects"}
            data["LongTermValues"] = []int{
                longTerm.SocialLife,
                longTerm.Academics,
                longTerm.CoCurriculum,
                longTerm.ExtraCurriculum,
                longTerm.Health,
                longTerm.SelfProjects,
            }
            data["LastWeekValues"] = []int{
                last.SocialLife,
                last.Academics,
                last.CoCurriculum,
                last.ExtraCurriculum,
                last.Health,
                last.SelfProjects,
            }
        }

        return c.Render(http.StatusOK, "dashboard.html", data)
    }
}

// ---------- Set Long-Term handlers ----------
func handleSetLongTerm(db *pgxpool.Pool, store *sessions.CookieStore) echo.HandlerFunc {

    return func(c echo.Context) error {
    log.Println("🔥 handleSetLongTerm executed")//<--for debug log
        userID, err := getUserID(c, store)
        if err != nil {
            return c.Redirect(http.StatusFound, "/login")
        }

        // If user already has long-term, redirect to dashboard
        var exists bool
        err = db.QueryRow(context.Background(),
            "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND long_term != '{}'::jsonb)", userID).Scan(&exists)
        if err != nil {
            return c.String(http.StatusInternalServerError, "Database error")
        }
        if exists {
            return c.Redirect(http.StatusFound, "/dashboard")
        }

        categories := []map[string]string{
            {"Key": "social_life", "Name": "Social Life"},
            {"Key": "academics", "Name": "Academics"},
            {"Key": "co_curriculum", "Name": "Co-curriculum"},
            {"Key": "extra_curriculum", "Name": "Extra-curriculum"},
            {"Key": "health", "Name": "Health"},
            {"Key": "self_projects", "Name": "Self Projects"},
        }
        data := map[string]interface{}{
            "Categories": categories,
        }
        return c.Render(http.StatusOK, "set-long-term.html", data)
    }
}

func handleSetLongTermPost(db *pgxpool.Pool, store *sessions.CookieStore) echo.HandlerFunc {
    return func(c echo.Context) error {
        userID, err := getUserID(c, store)
        if err != nil {
            return c.Redirect(http.StatusFound, "/login")
        }

        // Parse form
        form, err := c.FormParams()
        if err != nil {
            return c.String(http.StatusBadRequest, "Invalid form")
        }

        // Build LongTerm struct
        lt := LongTerm{
            SocialLife:      toInt(form.Get("social_life")),
            Academics:       toInt(form.Get("academics")),
            CoCurriculum:    toInt(form.Get("co_curriculum")),
            ExtraCurriculum: toInt(form.Get("extra_curriculum")),
            Health:          toInt(form.Get("health")),
            SelfProjects:    toInt(form.Get("self_projects")),
        }

        // Validate total = 30
        total := lt.SocialLife + lt.Academics + lt.CoCurriculum + lt.ExtraCurriculum + lt.Health + lt.SelfProjects
        if total != 30 {
            return c.String(http.StatusBadRequest, "Total must be 30")
        }

        // Save to database
        _, err = db.Exec(context.Background(),
            "UPDATE users SET long_term = $1 WHERE id = $2", lt, userID)
        if err != nil {
            return c.String(http.StatusInternalServerError, "Database error")
        }

        return c.Redirect(http.StatusFound, "/dashboard")
    }
}

// ---------- Week Entry handlers ----------
func handleWeekEntry(db *pgxpool.Pool, store *sessions.CookieStore) echo.HandlerFunc {

    return func(c echo.Context) error {
    log.Println("🔥 handleWeekEntry executed")//<--for debug log
        userID, err := getUserID(c, store)
        if err != nil {
            return c.Redirect(http.StatusFound, "/login")
        }

        // Determine next week number
        var maxWeek int
        err = db.QueryRow(context.Background(),
            "SELECT COALESCE(MAX(week_number), 0) FROM weeks WHERE user_id=$1", userID).Scan(&maxWeek)
        if err != nil {
            return c.String(http.StatusInternalServerError, "Database error")
        }

        // Check if 7 days passed since last entry
        if maxWeek > 0 {
            var lastCreated time.Time
            err = db.QueryRow(context.Background(),
                "SELECT created_at FROM weeks WHERE user_id=$1 AND week_number=$2", userID, maxWeek).Scan(&lastCreated)
            if err != nil {
                return c.String(http.StatusInternalServerError, "Database error")
            }
            if time.Since(lastCreated).Hours() < 168 { // 7 days
                return c.Redirect(http.StatusFound, "/dashboard")
            }
        }

        categories := []map[string]string{
            {"Key": "social_life", "Name": "Social Life"},
            {"Key": "academics", "Name": "Academics"},
            {"Key": "co_curriculum", "Name": "Co-curriculum"},
            {"Key": "extra_curriculum", "Name": "Extra-curriculum"},
            {"Key": "health", "Name": "Health"},
            {"Key": "self_projects", "Name": "Self Projects"},
        }
        data := map[string]interface{}{
            "WeekNumber": maxWeek + 1,
            "Categories": categories,
        }
        return c.Render(http.StatusOK, "week-entry.html", data)
    }
}

func handleWeekEntryPost(db *pgxpool.Pool, store *sessions.CookieStore) echo.HandlerFunc {
    return func(c echo.Context) error {
        userID, err := getUserID(c, store)
        if err != nil {
            return c.Redirect(http.StatusFound, "/login")
        }

        form, err := c.FormParams()
        if err != nil {
            return c.String(http.StatusBadRequest, "Invalid form")
        }

        actual := WeekActual{
            SocialLife:      toInt(form.Get("social_life")),
            Academics:       toInt(form.Get("academics")),
            CoCurriculum:    toInt(form.Get("co_curriculum")),
            ExtraCurriculum: toInt(form.Get("extra_curriculum")),
            Health:          toInt(form.Get("health")),
            SelfProjects:    toInt(form.Get("self_projects")),
        }

        // Determine next week number
        var maxWeek int
        err = db.QueryRow(context.Background(),
            "SELECT COALESCE(MAX(week_number), 0) FROM weeks WHERE user_id=$1", userID).Scan(&maxWeek)
        if err != nil {
            return c.String(http.StatusInternalServerError, "Database error")
        }

        // Insert
        _, err = db.Exec(context.Background(),
            "INSERT INTO weeks (user_id, week_number, actuals) VALUES ($1, $2, $3)",
            userID, maxWeek+1, actual)
        if err != nil {
            return c.String(http.StatusInternalServerError, "Database error")
        }

        return c.Redirect(http.StatusFound, "/dashboard")
    }
}