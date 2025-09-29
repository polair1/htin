# Instalación Detallada

## Requisitos Previos

- Python 3.7 o superior
- pip (gestor de paquetes de Python)
- Git

## Linux/Ubuntu
```bash
# Actualizar sistema
sudo apt update
sudo apt install python3 python3-pip git

# Clonar repositorio
git clone https://github.com/polair1/htin.git
cd html-injection-scanner

# Crear entorno virtual (recomendado)
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Probar instalación
python3 htin2.py --version

"""macOS"""

# Instalar Homebrew (si no lo tienes)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Instalar Python
brew install python3

# Clonar e instalar
git clone https://github.com/polair1/htin.git
cd htin
pip3 install -r requirements.txt

"""Windows"""

# Descargar Python desde python.org
# Asegúrate de marcar "Add Python to PATH"

# Abrir PowerShell o CMD
git clone https://github.com/polair1/htin.git
cd htin
pip install -r requirements.txt
python htin2.py --version
