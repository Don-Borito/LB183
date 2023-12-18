
# Cybersecurity

Dieses Portfolio dient dazu mein wissen zu Cybersecurity weiter zu geben. Das Portfolio basiert auf dem wissen, dass ich im **Modul 183 Applikationssicherheit** implementieren erlernt habe.

## Aktuelle Bedrohungen
Um seine eigene Applikation zu schützen, muss man wissen, welche Bedrohungen existieren. Deshalb möchte ich kurz die am weitesten verbreiteten vorstellen. Ich werde nur die aktuell kritischsten Methoden erklären, basierend auf der Top Ten Liste von [OWASP](https://owasp.org/www-project-top-ten/). Bei OWASP gibt es ebenfalls Anleitungen, wie man gegen diese potenziellen Sicherheitslücken vorgehen kann.

### Broken Access Control
Broken Access Control bezeichnet Sicherheitsmängel, bei denen Benutzer unautorisierten Zugriff auf bestimmte Ressourcen oder Funktionen innerhalb eines Systems erlangen können. Diese Schwachstelle tritt auf, wenn die Implementierung der Zugriffskontrollmechanismen fehlerhaft oder unzureichend ist.

**Gegenmaßnahmen:**

1. **Rigorose Zugriffskontrollen implementieren:**
   - Implementiere klare und strenge Zugriffskontrollen, um sicherzustellen, dass nur autorisierte Benutzer auf bestimmte Ressourcen oder Funktionen zugreifen können.

2. **Prinzip des geringsten Privilegs anwenden:**
   - Gewähre Benutzern nur die minimalen Berechtigungen, die für ihre jeweiligen Aufgaben notwendig sind. Dies minimiert das Risiko von unautorisierten Zugriffen.

3. **Starke Authentifizierung und Autorisierung:**
   - Nutze starke Authentifizierungsmethoden, um sicherzustellen, dass Benutzer tatsächlich diejenigen sind, für die sie sich ausgeben. Kombiniere dies mit einer klaren Autorisierung, um sicherzustellen, dass authentifizierte Benutzer nur auf die für sie bestimmten Ressourcen zugreifen können.

4. **Regelmäßige Überprüfung und Audits:**
   - Führe regelmäßige Überprüfungen der Zugriffsberechtigungen durch und führe Sicherheitsaudits durch, um mögliche Schwachstellen zu identifizieren und zu beheben.

5. **Monitoring und Protokollierung:**
   - Implementiere ein Überwachungssystem, das verdächtige Aktivitäten erkennt und protokolliert, um ungewöhnlichen Zugriff oder unberechtigte Handlungen frühzeitig zu erkennen.

6. **Schulung der Benutzer:**
   - Sensibilisiere die Benutzer für sichere Zugriffspraktiken und erkläre, warum die Einhaltung von Zugriffsregelungen wichtig ist, um das Bewusstsein für Sicherheitsrisiken zu schärfen.

### Cryptographic Failures
Cryptographic Failures beziehen sich auf Schwachstellen oder Mängel in der Anwendung von kryptografischen Techniken (Verschlüsselung), die die Sicherheit von Systemen und Daten gefährden können. Diese Fehler können durch unsachgemäße Implementierung, Schwächen in den verwendeten Algorithmen oder mangelnde Aktualisierung der kryptografischen Standards verursacht werden.

**Gegenmaßnahmen:**

1. **Verwendung aktueller und sicherer Algorithmen:**
   - Implementiere nur kryptografische Algorithmen, die als sicher und aktuell gelten. Veraltete Algorithmen sind anfällig für Angriffe.

2. **Sorgfältige Implementierung und Verwendung bewährter Bibliotheken:**
   - Stelle sicher, dass die kryptografischen Funktionen korrekt und sicher implementiert sind. Die Verwendung von bewährten kryptografischen Bibliotheken reduziert das Risiko von Implementierungsfehlern.

3. **Regelmäßige Aktualisierung und Überwachung:**
   - Halte kryptografische Standards und Implementierungen auf dem neuesten Stand, um Schwächen zu beheben. Überwache kontinuierlich die kryptografischen Verfahren, um auf neue Bedrohungen reagieren zu können.

4. **Schulung und Sensibilisierung der Entwickler:**
   - Schulung der Entwickler in Bezug auf bewährte Praktiken bei der Implementierung von kryptografischen Techniken, um Fehler in der Anwendung zu minimieren.

5. **Sicherheitsaudits und Penetrationstests:**
   - Führe regelmäßig Sicherheitsaudits und Penetrationstests durch, um potenzielle kryptografische Schwachstellen zu identifizieren und zu beheben.

### Injection

Injection bezeichnet eine Sicherheitslücke, bei der unerwünschter Code in eine Anwendung eingeschleust wird und dann vom System ausgeführt wird. Dieser Angriffstyp tritt oft auf, wenn Benutzereingaben nicht ausreichend validiert oder gesäubert werden, bevor sie in Datenbankabfragen, Befehle oder andere Ausführungsumgebungen eingefügt werden.

**Gegenmaßnahmen:**

1. **Parameterized Statements und Prepared Statements:**
   - Verwende parametrisierte Abfragen oder vorbereitete Anweisungen, um sicherzustellen, dass Benutzereingaben nicht direkt in Abfragen eingefügt werden, sondern als Parameter behandelt werden.

2. **Input Validation:**
   - Validiere und filtere alle Benutzereingaben, um sicherzustellen, dass sie den erwarteten Formaten entsprechen. Dies minimiert das Risiko unerlaubter Einfügungen von Code.

3. **Escaping von Zeichen:**
   - Escape-Zeichen in Benutzereingaben, um sicherzustellen, dass sie als reine Daten behandelt werden und nicht als ausführbarer Code.

4. **Least Privilege Principle:**
   - Gewähre Anwendungen nur die minimalen Berechtigungen, die für ihre Funktionen erforderlich sind. Dadurch wird das Schadenspotenzial bei erfolgreichen Injection-Angriffen minimiert.

5. **Regelmäßige Sicherheitsaudits:**
   - Führe regelmäßige Sicherheitsaudits durch, um potenzielle Injection-Schwachstellen zu identifizieren und zu beheben.

6. **Verwendung von Web Application Firewalls (WAF):**
   - Implementiere Web Application Firewalls, um verdächtigen Datenverkehr zu überwachen und Angriffsversuche auf Injection zu erkennen und zu blockieren.

## Sicherheitslücken einer Applikation erkennen
```csharp
public ActionResult<User> Login(LoginDto request)
        {
            if (request == null || request.Username.IsNullOrEmpty() || request.Password.IsNullOrEmpty())
            {
                return BadRequest();
            }

            string sql = string.Format("SELECT * FROM Users WHERE username = '{0}' AND password = '{1}'", 
                request.Username, 
                MD5Helper.ComputeMD5Hash(request.Password));

            User? user= _context.Users.FromSqlRaw(sql).FirstOrDefault();
            if (user == null)
            {
                return Unauthorized("login failed");
            }
            return Ok(user);
        }
```
In diesem Beispiel gibt es eine Sicherheitslücke bei der Verarbeitung der Logindaten. Aus den Eingaben wird direkt ein SQL String erstellt, das hat zur Folge, dass der SQL String nach Belieben verändert werden kann. 
Als Beispiel kann bei Username ``admin'--`` eingegeben werden. Das hat zur Folge, dass das neue SQL Statement wie folgt aussieht: 
```sql
SELECT * FROM Users WHERE username = 'admin'--' AND password = '{1}'
```
Nun wird in der Datenbank nur noch gesucht, ob ein Nutzer mit Namen admin vorhanden ist und dann der Zugriff gewährt, da der Rest mit dem Passwort auskommentiert ist.

## Gegenmassnahmen vorschlagen und implementieren

```csharp
public ActionResult<User> Login(LoginDto request)
        {
            if (request == null || request.Username.IsNullOrEmpty() || request.Password.IsNullOrEmpty())
            {
                return BadRequest();
            }

            string username = request.Username;
            string passwordHash = MD5Helper.ComputeMD5Hash(request.Password);

            User? user = _context.Users
                .Where(u => u.Username == username)
                .Where(u => u.Password == passwordHash)
                .FirstOrDefault();

            if (user == null)
            {
                return Unauthorized("login failed");
            }
            return Ok(user);
        }
```
In dieser Lösung wird das Problem behoben, indem der SQL String nicht direkt im Programm erstellt wird, sondern eine LINQ-Abfrage verwendet wird.

Hier noch zwei Vorteile der LINQ-Abfragen gegenüber direkten SQL Abfragen:

**Parameterisierung von Abfragen:** LINQ-Abfragen werden oft als parametrisierte Abfragen erstellt, bei denen Werte als Parameter übergeben werden, anstatt sie direkt in die Abfrage einzubetten. Dies reduziert das Risiko von SQL-Injections erheblich, da Benutzereingaben nicht direkt in die SQL-Abfrage eingefügt werden.

**Automatische Escapen von Zeichen:** LINQ-to-SQL- oder Entity Framework-Anbieter handhaben oft das Escapen von Sonderzeichen automatisch. Dies hilft, potenziell schädliche Zeichen zu neutralisieren, was das Risiko von SQL-Injections weiter minimiert.

## Mechanismen für die Authentifizierung und Autorisierung umsetzen können

## Authentifizierung
  
```csharp
private string CreateToken(User user)
        {
            string issuer = _configuration.GetSection("Jwt:Issuer").Value!;
            string audience = _configuration.GetSection("Jwt:Audience").Value!;

            List<Claim> claims = new List<Claim> {
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.NameId, user.Id.ToString()),
                    new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
                    new Claim(ClaimTypes.Role,  (user.IsAdmin ? "admin" : "user"))
            };

            string base64Key = _configuration.GetSection("Jwt:Key").Value!;
            SymmetricSecurityKey securityKey = new SymmetricSecurityKey(Convert.FromBase64String(base64Key));

            SigningCredentials credentials = new SigningCredentials(
                    securityKey,
                    SecurityAlgorithms.HmacSha512Signature);

            JwtSecurityToken token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                notBefore: DateTime.Now,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: credentials
             );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
```


Dieser Code implementiert die Erstellung eines JSON Web Tokens (JWT) als Mechanismus für die Authentifizierung. Ein JWT ist eine kompakte, URL-sichere Möglichkeit, Informationen zwischen Parteien zu übertragen. In diesem Fall wird der JWT verwendet, um einen Benutzer zu authentifizieren.
Im Allgemeinen werden JWT Token verwendet, damit bei jeder erneuten Anfrage an den Server kontrolliert werden kann ob der Benutzer dazu berechtigt ist, ohne jedes Mal die Benutzerdaten abzufragen.

Funktionsweise von JWT Tokens:

1. **Lesen der Konfiguration:**
   ```csharp
   string issuer = _configuration.GetSection("Jwt:Issuer").Value!;
   string audience = _configuration.GetSection("Jwt:Audience").Value!;
   ```
   Hier werden die Werte für den Aussteller (issuer) und das Publikum (audience) aus der Konfigurationsdatei geladen. Der Aussteller ist normalerweise der Server, der den Token ausgibt, und das Publikum ist der beabsichtigte Empfänger des Tokens.

2. **Erstellen von Ansprüchen (Claims):**
   ```csharp
   List<Claim> claims = new List<Claim> {
       new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
       new Claim(JwtRegisteredClaimNames.NameId, user.Id.ToString()),
       new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
       new Claim(ClaimTypes.Role,  (user.IsAdmin ? "admin" : "user"))
   };
   ```
   Hier werden Ansprüche erstellt, die im JWT enthalten sind. Diese Ansprüche können Informationen wie die Benutzer-ID, den Benutzernamen und die Rolle des Benutzers enthalten.

3. **Erstellen des Sicherheitsschlüssels:**
   ```csharp
   string base64Key = _configuration.GetSection("Jwt:Key").Value!;
   SymmetricSecurityKey securityKey = new SymmetricSecurityKey(Convert.FromBase64String(base64Key));
   ```
   Der Sicherheitsschlüssel wird aus dem in der Konfiguration angegebenen Base64-codierten Schlüssel erstellt. Dieser Schlüssel wird verwendet, um den Token zu signieren und sicherzustellen, dass er von einer vertrauenswürdigen Quelle stammt.

4. **Erstellen von Anmeldeinformationen (Credentials):**
   ```csharp
   SigningCredentials credentials = new SigningCredentials(
       securityKey,
       SecurityAlgorithms.HmacSha512Signature);
   ```
   Die Anmeldeinformationen enthalten den Sicherheitsschlüssel und den Algorithmus (HMAC-SHA512), der zur Signierung des Tokens verwendet wird.

5. **Erstellen des JWT:**
   ```csharp
   JwtSecurityToken token = new JwtSecurityToken(
       issuer: issuer,
       audience: audience,
       claims: claims,
       notBefore: DateTime.Now,
       expires: DateTime.Now.AddDays(1),
       signingCredentials: credentials
   );
   ```
   Hier wird das eigentliche JWT erstellt, indem alle zuvor erstellten Komponenten (Aussteller, Publikum, Ansprüche, Ablaufzeit usw.) berücksichtigt werden.

6. **Rückgabe des Tokens als Zeichenkette:**
   ```csharp
   return new JwtSecurityTokenHandler().WriteToken(token);
   ```
   Schließlich wird der JWT als Zeichenkette zurückgegeben, sodass er an den Benutzer oder Client gesendet werden kann.

Insgesamt generiert dieser Code also einen JWT-Token, der die Identität und ggf. die Rolle des authentifizierten Benutzers repräsentiert. Dieser Token kann dann für weitere Anfragen an den Server verwendet werden, um die Authentizität des Benutzers zu überprüfen.

### Autorisierung

Die Autorisierung in der App-Entwicklung bezieht sich auf den Prozess der Identifizierung und Überprüfung von Benutzern, um sicherzustellen, dass sie die erforderlichen Berechtigungen haben, auf bestimmte Ressourcen oder Funktionen der Anwendung zuzugreifen. Dieser Prozess ist entscheidend, um die Sicherheit der Anwendung zu gewährleisten und den unbefugten Zugriff auf sensible Daten zu verhindern. Die Autorisierung kann bei einer Server Anfrage zum Beispiel durch den beim Login erstellten JWT-Token erfolgen.


