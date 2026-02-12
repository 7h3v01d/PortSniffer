import sys
from PyQt6.QtWidgets import QApplication
from gui import NetworkMonitor
import logging

logging.basicConfig(filename='network_monitor.log', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

if __name__ == "__main__":
    logging.info("Starting application...")
    app = QApplication(sys.argv)
    logging.info("Creating NetworkMonitor window...")
    window = NetworkMonitor()
    logging.info("Showing window...")
    window.show()
    logging.info("Application running...")
    sys.exit(app.exec())