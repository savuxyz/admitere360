# RoAdmitere

Platforma pentru admiterea la facultate: candidatul isi face cont, isi completeaza profilul si dosarul, apoi aplica la una sau mai multe universitati.

Proiect de echipa la disciplina Instrumente software pentru grupuri de lucru. Taskurile sunt in Jira, proiectul ADMITERE.

## Cerinte

- Node.js 22.13 sau mai nou (`node -v`)
- Git

## Cum pornesti proiectul

```
git clone https://github.com/savuxyz/admitere360.git
cd admitere360
npm start
```

Apoi deschizi http://localhost:3000. Nu trebuie `npm install`, proiectul nu are pachete externe. Opresti serverul cu Ctrl+C.

Teste: `npm test`

## Conturi demo

Parola pentru toate: `demo1234`

- Candidat: `ana@exemplu.demo`
- Operator Aurora: `operator@aurora.demo`
- Administrator Aurora: `admin@aurora.demo`

Datele se salveaza in `data/roadmitere.db`. Ca sa pornesti de la zero, stergi folderul `data`.

## Cum lucram

1. Iei un task din Jira si il muti in In curs.
2. Faci un branch nou din `main`, cu cheia taskului in nume:
   `git checkout -b ADMITERE-49-autentificare`
3. Faci modificarile. Fiecare commit incepe cu cheia taskului:
   `git commit -m "ADMITERE-49: pagina de login"`
4. Urci branch-ul (`git push -u origin ADMITERE-49-autentificare`) si deschizi un Pull Request.
5. Un coleg verifica PR-ul si il aproba, apoi se face merge in `main`.
6. Muti taskul in Done si pui linkul PR-ului in comentariu.

## Reguli

- Nu lucram direct pe `main`.
- Nu punem in repository parole, chei, fisiere `.env` sau baze de date.
- Folosim doar date fictive (ex. `ana@exemplu.demo`).
