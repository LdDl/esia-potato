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

w.i.p.

## Вводные

w.i.p.

## Структура проекта

```
esia-potato/
|--- cms/
|    --- cms.go                  
|--- cryptopro/
|    --- extract.go               # Библиотека извлечения ключей
|--- cmd/
|    --- cryptopro_extract/
|        --- main.go              # CLI для извлечения ключей
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
  git clone git@github.com:LdDl/esia-potato.git ---depth 1
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

Результат, если всё

```
{"time":"2025-12-29T20:36:00.591340886+03:00","level":"INFO","msg":"container opened","path":"./test_container","curve_oid":"1.2.643.2.2.36.0"}
{"time":"2025-12-29T20:36:01.065829042+03:00","level":"INFO","msg":"primary key extracted","curve_oid":"1.2.643.2.2.36.0","fingerprint":"0123456789abcdef","private_key":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"}
{"time":"2025-12-29T20:36:01.065854001+03:00","level":"WARN","msg":"secondary key found but not extracted","masks":"masks2.key","primary":"primary2.key"}
{"time":"2025-12-29T20:36:01.065858097+03:00","level":"INFO","msg":"done"}
```

Если отображается сообщение с предупреждением:
```
Note: secondary key (masks2.key/primary2.key) found but not extracted
````
, то это нормально — вторичный ключ не нужен для подписи, т.к. для oAuth в ЕСИА используется только первичный ключ.

Теперь у нас есть приватный ключ, который нужно использовать для подписи запросов к ЕСИА.

## Пример клиента ЕСИА

w.i.p.