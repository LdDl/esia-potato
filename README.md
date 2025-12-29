# ESIA oAuth клиент на Go

Попытка сделать нативную реализацию oAuth через ЕСИА с поддержкой криптографии по ГОСТ.
Без готовых Docker сборок с пропатченным OpenSSL или внешних зависимостей от OpenSSL как такового.

## Содержание
- [Что умеет](#что-умеет)
- [Вводные](#вводные)
- [Структура проекта](#структура-проекта)
- [Установка](#установка)
- [Извлечение приватного ключа из контейнера КриптоПро](#извлечение-приватного-ключа-из-контейнера-криптопро)
- [Пример клиента ЕСИА](#пример-клиента-есиа)

## Что умеет

- Подпись ГОСТ Р 34.10-2012 (256 бит)
- Хеш ГОСТ Р 34.11-2012 (Стрибог-256)
- Формирование CMS/PKCS#7 SignedData
- Работа с ключами из контейнера КриптоПро

## Вводные

- Для сборки из исходников нужен Go 1.21+
- Контейнер КриптоПро с приватным ключом и сертификатом. В данном случае "контейнер" - это директория (или архив изначально), которая создаётся при экспорте ключа из КриптоПро CSP.

## Структура проекта

```
esia-potato/
|--- cms/
|    --- cms.go                   # CMS/PKCS#7 SignedData
|--- cryptopro/
|    --- extract.go               # Библиотека извлечения ключей
|--- utils/
|    --- bytes.go                 # Вспомогательные функции
|--- cmd/
|    |--- cryptopro_extract/
|    |    --- main.go             # CLI для извлечения ключей
|    `--- example/
|         --- main.go             # Пример клиента ЕСИА
`--- test_container/              # Тестовые ключи. В gitignore, так как ваши будут отличаться
```

## Установка

* Для утилиты извлечения ключей из контейнера КриптоПро
- Если нужен просто CLI:
  ```bash
  go install github.com/LdDl/esia-potato/cmd/cryptopro_extract@latest
  cryptopro_extract -h
  ```

- Если хочешь собрать из исходников:
  ```bash
  git clone git@github.com:LdDl/esia-potato.git --depth 1
  cd esia-potato
  go run ./cmd/cryptopro_extract -h
  ```

## Извлечение приватного ключа из контейнера КриптоПро

Контейнер КриптоПро хранит ключи в проприетарном формате с шифрованием [ГОСТ 28147](https://ru.wikipedia.org/wiki/%D0%93%D0%9E%D0%A1%D0%A2_28147-89).

- С помощью установленного CLI:
  ```bash
  cryptopro_extract -p ПИН_КОД_ПАРОЛЬ ./container.000
  ```

- Или из исходников:
  ```bash
  go run ./cmd/cryptopro_extract -p ПИН_КОД_ПАРОЛЬ ./container.000
  ```

Если всё ОК, то в консоли будет что-то типа:

```
{"time":"2025-12-29T20:36:00.591340886+03:00","level":"INFO","msg":"container opened","path":"./test_container","curve_oid":"1.2.643.2.2.36.0"}
{"time":"2025-12-29T20:36:01.065829042+03:00","level":"INFO","msg":"primary key extracted","curve_oid":"1.2.643.2.2.36.0","fingerprint":"0123456789abcdef","private_key":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"}
{"time":"2025-12-29T20:36:01.065854001+03:00","level":"WARN","msg":"secondary key found but not extracted","masks":"masks2.key","primary":"primary2.key"}
{"time":"2025-12-29T20:36:01.065858097+03:00","level":"INFO","msg":"done"}
```

Если отображается сообщение с предупреждением:
```
secondary key found but not extracted
````
, то это нормально — вторичный ключ не нужен для подписи, т.к. для oAuth в ЕСИА используется только первичный ключ.

Теперь у нас есть приватный ключ, который нужно использовать для подписи запросов к ЕСИА.

## Пример клиента ЕСИА

- Возьмите приватный ключ из вывода предыдущего шага и вставьте его в `cmd/example/main.go` в `keyHex`.
- Запустите пример:
  ```bash
  go run ./cmd/example/main.go
  ```

Если всё ОК, то в консоли будет что-то типа:
```
{"time":"2025-12-29T20:47:23.876107574+03:00","level":"INFO","msg":"message prepared","message":"openid2025.12.29 17:47:23 +0000775607_DP0f9439ef-3581-4de5-9b8c-d20135960331"}
{"time":"2025-12-29T20:47:23.878111012+03:00","level":"INFO","msg":"signature created","signature_bytes":2927,"base64_chars":3904}
{"time":"2025-12-29T20:47:23.8781677+03:00","level":"INFO","msg":"authorization URL prepared","url":"https://esia-portal1.test.gosuslugi.ru/aas/oauth2/ac?access_type=offline&client_id=775607_DP&client_secret=гигантский_jwt_токен&redirect_uri=https%3A%2F%2Fya.ru&response_type=code&scope=openid&state=0f9439ef-3581-4de5-9b8c-d20135960331&timestamp=2025.12.29+17%3A47%3A23+%2B0000"}
{"time":"2025-12-29T20:47:23.878185114+03:00","level":"INFO","msg":"testing against ESIA"}
{"time":"2025-12-29T20:47:23.95390256+03:00","level":"INFO","msg":"response received","status":"302 ","location":"https://esia-portal1.test.gosuslugi.ru/login"}
{"time":"2025-12-29T20:47:23.953918261+03:00","level":"INFO","msg":"signature accepted by ESIA"}
```

Редирект на /login означает, что подпись прошла проверку и всё ок.
