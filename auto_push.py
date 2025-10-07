import os
import time
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class GitAutoPush(FileSystemEventHandler):
    def __init__(self, repo_path):
        self.repo_path = repo_path

    def on_any_event(self, event):
        if event.is_directory:
            return

        os.chdir(self.repo_path)
        print("💾 Cambio detectado, verificando diferencias...")

        # Verifica si hay cambios pendientes
        status = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True)

        if status.stdout.strip() == "":
            print("⚙️ No hay cambios nuevos, no se realizará commit.\n")
            return

        # Si hay cambios, hace commit y push
        os.system("git add .")
        os.system('git commit -m "Actualización automática"')
        os.system("git push origin master")  # Cambia 'main' si tu rama es diferente

        print("✅ Cambios subidos correctamente a GitHub.\n")

if __name__ == "__main__":
    # 🔧 Ruta del repositorio local
    repo_path = r"D:\INVENTARIO_FLASK"  # cámbiala si tu proyecto está en otro lugar

    event_handler = GitAutoPush(repo_path)
    observer = Observer()
    observer.schedule(event_handler, path=repo_path, recursive=True)
    observer.start()

    print("👀 Monitoreando cambios en tu proyecto (INVENTARIO_FLASK)...")
    print("Presiona CTRL + C para detener.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("🛑 Monitoreo detenido.")
    observer.join()
