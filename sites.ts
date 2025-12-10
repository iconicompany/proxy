// index.ts

// Тип для выходного объекта
type ProxyItem = {
    hostname: string;
    ip: string;
};

// 1. Читаем переменную окружения
const rawEnv = Bun.env.PROXY_DIRECT_IPV4;

if (!rawEnv) {
    console.error("Ошибка: Переменная PROXY_DIRECT_IPV4 не найдена в .env файле");
    process.exit(1);
}

// 2. Обрабатываем строку
const result: ProxyItem[] = rawEnv
    // Удаляем все пробелы и переносы строк внутри строки (на случай "грязного" ввода)
    .replace(/\s+/g, '') 
    // Разбиваем по запятой
    .split(',')
    // Фильтруем пустые строки (на случай лишней запятой в конце)
    .filter((cidr) => cidr.length > 0)
    // Преобразуем в нужный формат объекта
    .map((cidr) => ({
        hostname: cidr,
        ip: ""
    }));

// 3. Выводим JSON в консоль
console.log(JSON.stringify(result, null, 4));

// Опционально: если нужно сохранить в файл, раскомментируй строку ниже:
// await Bun.write("output.json", JSON.stringify(result, null, 4));
