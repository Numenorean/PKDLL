![](https://telemetr.me/photos/697256229bf60a9c56ab6ea1e7d7d8ea.jpg)

## Что это?
Многие, наверное, не знают, но киппер поддерживает достаточно мощную концепцию использование сторонних функций, помимо JS - DLL библиотеки. С их помощью можно реализовать буквально все, чего нет в киппер - от банальной рандом функции (min, max), до реализации поддержки кастомных протоколов (WS, TCP) и скачивания картинок. Возможности поистинну безграничны, хотя есть одно но - чтобы самому писать такие либы придется выучить Go до базового уровня, пройдя GoTour

## Как оно работает?
Во-первых нужно понять, что киппер поддерживает только строковые типы данных как аргументы функции, тоже самое с возвращемым значение - только одно, только строка. Так же стоит отметить, что киппер написан на Delphi, то есть в идеале и либу писать нужно на нем ~~(но мы же не мазохисты)~~ потому-что Go, естественно, не поддерживает такие строковые типы как PChar и PWideChar - пришлось накидать небольшые функции для преобразования гошной строки в дельфийскую(?) и наоборот, на производительности, вроде, не сильно сказалось, но баги быть могут.

## Как использовать (разработчикам)?
Во-первых - только тип *C.wchar_t (никаких int, string и []byte), для этого есть функии stringToPWideCharPtr и PWideCharPtrToString, во-вторых - только одно возвращаемое значение (используйте разделители) и уже в киппере распарсите выходную строку. Чтобы экспортировать функцию добавляем сверху определения функции комментарий `//export %FUNC_NAME%`. Есть DEBUG режим, в котором создается консоль для более-менее удобного дебага, пишем туда обычными методами, но аккуратно - закрыв консоль, вы закроете киппер. Так же не уверен, есть ли смысл использовать горутины. Что нужно чтобы сбилдить длл: во-первых нужно установить TDM-GCC/MinGW, добавить папку bin в path, далее правим make.bat и меняем BINARYNAME на нужное имя

## Как использовать (пользователям)?
Открываем Студию -> Обзор локальных плагинов -> Установить -> Выбираем нужную дллку (аккуратно, не открывайте все подряд, т.к. по сути это тот же exe, вы же не хотите словить стиллер)

## Баги
Это печально, но они есть. Самый крупный из них - вылет киппера когда удаляешь дллку из студии, скорее всего из-за особенностей делфи, киппер пытается вызвать что-то, чего нет в моей длл. Так же иногда происходит вылет при бруте. Пофиксить нет возможности - дебажить киппер я не могу