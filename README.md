# L2Enc

Cifra e decifra arquivos do cliente de Lineage II. Basta arrastar os arquivos para o `L2Enc.exe`: o que estiver cifrado é decifrado e o que estiver aberto é cifrado, no próprio lugar.

## Formatos

| Formato | Decifra | Cifra |
|---|---|---|
| `Lineage2Ver111` | ✔ | ✔ |
| `Lineage2Ver120` | ✔ | |
| `Lineage2Ver121` | ✔ | ✔ |
| `Lineage2Ver211` / `212` | ✔ | |
| `Lineage2Ver413` (RSA + zlib) | ✔ | ✔ |
| Áudio OGG | ✔ | ✔ |

O L2Enc detecta sozinho se o arquivo já está cifrado. Para cifrar um arquivo aberto, ele escolhe o formato pela extensão:

- **121**: texturas (`utx`, `ugx`, `bmp`)
- **111**: pacotes (`u`, `uax`, `unr`, `uix`, `ukx`, `usx`, `usk`) e textos (`htm`, `int`, `interface.xdat`, `ttfontinfo.ini`, `localization.ini`)
- **413**: tabelas `.dat`, `l2.ini` e `user.ini`
- **OGG**: arquivos `.ogg`

## Como usar

**Arrastar e soltar:** arraste um ou mais arquivos sobre o `L2Enc.exe`. A janela mostra o andamento de cada arquivo e espera um Enter no final.

**Linha de comando:**

```
L2Enc.exe <arquivo> [<arquivo> ...]
```

Cada arquivo ganha uma linha com a operação feita e o resultado. O código de saída é `0` quando todos dão certo e `1` quando algum falha.

> O arquivo original é substituído pelo resultado. Guarde uma cópia se precisar da versão anterior.

## Compilação

Requer Rust (edição 2024) e, no Windows, o Windows SDK (para o ícone e as informações de versão do executável).

```
make build
```

O executável sai em `target/release/L2Enc.exe`. Para rodar os testes: `cargo test`.

## Licença

[MIT](LICENSE) © 2026 Mk (Majestic World Studio)
