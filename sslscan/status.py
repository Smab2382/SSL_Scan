from enum import Enum
class Status(Enum):
    stOk = 1 # всё хорошо
    stVuln = 2 # ЕСТЬ УЯЗВИМОСТЬ
    stError = 3 # ОШИБКА ПРИ ПОДКЛЮЧЕНИИ
    stUnknown = 4 # неизвестно