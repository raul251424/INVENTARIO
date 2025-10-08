# Ruta del ejecutable de Git (cambia si tu ruta es distinta)
$gitPath = "C:\Program Files\Git\cmd\git.exe"

# Mensaje automático de commit con fecha y hora
$date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$commitMessage = "Auto-commit: $date"

# Ir a la carpeta del proyecto (cambia si tu proyecto está en otra ruta)
Set-Location "D:\INVENTARIO_FLASK"

# Agregar todos los archivos al commit
& $gitPath add .

# Crear commit con mensaje automático
& $gitPath commit -m $commitMessage

# Subir los cambios al repositorio remoto
& $gitPath push
