# Ruta del ejecutable de Git
$gitPath = "C:\Program Files\Git\cmd\git.exe"

# Ir al directorio del proyecto
Set-Location "D:\INVENTARIO_FLASK"

# Detectar si hay cambios (archivos nuevos, modificados o eliminados)
$changes = & $gitPath status --porcelain

if ($changes) {
    # Mensaje automático de commit con la hora actual
    $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $commitMessage = "Auto-commit: cambios detectados el $date"

    Write-Host "🔹 Cambios detectados. Haciendo commit y push..." -ForegroundColor Cyan
    
    # Agregar todos los cambios
    & $gitPath add .

    # Crear el commit
    & $gitPath commit -m $commitMessage

    # Subir cambios al repositorio remoto
    & $gitPath push

    Write-Host "✅ Cambios subidos correctamente a GitHub." -ForegroundColor Green
} 
else {
    Write-Host "🟢 No hay cambios nuevos, no se realizó ningún commit." -ForegroundColor Yellow
}
