# etnop-chatbot-raw

# Felvételi feladat

A feladatod egy AI chatbot REST API implementálása Python és FastAPI segítségével.

## Feladatleírás

Szeretnél egy AI chatbotot létrehozni, amely lehetővé teszi a felhasználók számára,
hogy szöveges üzeneteket küldjenek és fogadjanak.
A chatbotnak képesnek kell lennie az utolsó 10 üzenet külső AI szolgáltatáshoz
történő továbbítására és annak válaszainak fogadására.

## Feladatok

- Implementáld a feladatot:
  - Nyelv: **Python**
  - Keretrendszer: **FastAPI**
  - A többi könyvtár szabadon választható
  
- Implementálj egy végpontot a korábbi üzenetek lekérdezésére, ami nyilvánosan elérhető
- Implementálj egy végpontot az üzenetek beküldésére, amihez szükséges valamilyen authentikáció (pl. basic, API key, JWT)
- Hívj meg egy külső szolgáltatást az utolsó, maximum 10 üzenettel, és fogadd az arra érkező választ. (A külső szolgáltatás válaszában benne van a válaszüzenet.)
- Mockold az adattárolást és a külső AI szolgáltatót

- A kód legyen jól struktúrált, továbbfejleszthető, tesztelhető és "production ready". Mintha egy zöldmezős projekt első funkcióján dolgoznál.

- Írj unit és integrációs (API) teszteket. Egy pár teszt elég, nem kell minden eshetőséget letesztelni.

### Opcionális feladatok - örülnénk ha látnánk valamelyik(ek)re a megoldásod

- Implementáld az adatok tárolását egy adatbázisban - Pl. Postgres
- Implementálj rate-limitet az üzenet beküldéshez. (3 üzenet / perc / felhasználó)
- Garantáld, hogy a user-bot-user-bot... sorrend mindig betartásra kerül
- Integráld az OpenAI GPT-3.5 szolgáltatást alternatív implementációként
- Implementálj egy végpontot, ami felhasználónév és jelszó alapján kiállít egy JWT access tokent, amivel a felhasználók authentikálhatnak a többi végponthoz
- Az üzenetek előzményeit ne 10 üzenetre szűkítsd, hanem inkább maximum 500 szóra. Ha szeretnéd, alkalmazz token becslés alapú vágást!

## Értékelési kritériumok

- **Python** legjobb gyakorlatai
- A kód legyen jól struktúrált és könnyen továbbfejleszthető

## Kód beküldés

A kód beküldéséhez készíts egy saját repository-t a GitHub-on és tedd azt nyilvánossá.
Miután feltöltötted a kódod a master ágra, küldd el a repository linkjét emailben.

Fontos, hogy figyelj oda a Git commitokra, mivel ezeket is értékelni fogjuk.

Sok sikert és kellemes kódolást!
