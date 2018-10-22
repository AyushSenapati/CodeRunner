from django.apps import AppConfig
import logging

logger = logging.getLogger(__name__)


class CoderunnerConfig(AppConfig):
    name = 'coderunner'
    verbose_name = 'CodeRunner'

    def ready(self):
        """Override ready() method to register
        signals for when the application is ready
        """
        import coderunner.signals  # Register the signal
        logger.info(f'{self.name} signals has been registered successfully.')
