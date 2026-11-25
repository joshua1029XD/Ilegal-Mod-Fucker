# Ilegal Fucker - Screenshare Scanner

Herramienta de revision para SS (screenshare) de Minecraft Java. Detecta cheats y mods ilegales
en la instancia del jugador. **Solo lectura**: no modifica, borra ni envia nada.

## Uso (un solo comando, en PowerShell)

```powershell
irm https://raw.githubusercontent.com/joshua1029XD/Ilegal-Fucker/main/IlegalFucker.ps1 | iex
```

No descarga archivos ni pide datos. Detecta solo el Minecraft que esta abierto y las instancias
de los launchers (.minecraft, Prism, MultiMC, CurseForge, Modrinth, ATLauncher, GDLauncher).

Guardar el reporte en el escritorio y mostrar tambien los mods limpios:

```powershell
iex "& { $(irm https://raw.githubusercontent.com/joshua1029XD/Ilegal-Fucker/main/IlegalFucker.ps1) } -All -Out $env:USERPROFILE\Desktop\reporte.txt"
```

## Novedades (v1.2)

- Banner nuevo "Ilegal Fucker" con la barrera de Minecraft pixelada
- Deteccion por comportamiento de mods prohibidos renombrados o con bypass (NoInputLag/FastPlace, NoJumpDelay, FastTotem/TotemUtils)
- Menos falsos positivos (Kotlin, spark, rhino, ModMenu, ImmediatelyFast...)
- Autodeteccion del Minecraft abierto y de las instancias de los launchers

## Que detecta

- Clientes y hacks conocidos (firmas en clases, recursos, strings y metadatos)
- Ofuscacion (clases a/b/c, nombres tipo Il1I, unicode raro, sin metadatos)
- Funciones de totem tipo hack (AutoTotem, HoverTotem, TotemHit, offhand swap...)
- Herramientas de evasion: self-destruct, anti-SS, limpiadores de rastros, spoofers
- Java Agents (`-javaagent`), argumentos sospechosos de la JVM y carpetas de mods ocultas
- Codigo que revisa procesos o ejecuta comandos (tasklist, powershell, wmic...)
- Mods prohibidos RENOMBRADOS / con bypass: detecta su comportamiento (delays de click/minado, salto, clicks de slot del totem) aunque cambien de nombre, id o paquete
- Suplantacion de mods conocidos (un jar que dice ser Krypton, Sodium, etc. con otro codigo)
- Mods prohibidos por reglas (lista editable `$BANNED_MODS` al inicio del script)
- Jars disfrazados (.txt/.zip), .exe/.dll/.bat dentro de /mods, nombres reservados de Windows
- Logs borrados o vacios y menciones de hacks en logs
- Hashes: lista blanca y lista negra

## Opciones

| Parametro | Descripcion |
|---|---|
| `-Path` | Revisar solo una instancia o carpeta mods concreta |
| `-All` | Mostrar tambien los mods limpios |
| `-Out` | Guardar el reporte en un archivo |
| `-MakeWhitelist` | Guardar los hashes de los mods actuales como lista blanca |
| `-Whitelist` | Marcar mods cuyo hash no este en la lista blanca |
| `-BadHashes` | Archivo con hashes prohibidos (uno por linea) |
| `-BannedIds` | JSON `{id: motivo}` con mods prohibidos extra |
| `-RecentHours` | Marcar archivos modificados hace menos de N horas |

## Limitaciones

- Es una ayuda para el staff, no una prueba definitiva: revisa siempre el resultado a mano.
- Un mod ofuscado no es necesariamente un hack (algunos mods legitimos usan ProGuard).
- No detecta clientes inyectados en memoria (DLL / ghost clients).
