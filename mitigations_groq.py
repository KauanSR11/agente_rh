# Camadas de mitigação para o Assistente de RH.

import random
import re

import sqlparse
from sqlparse.sql import IdentifierList, Identifier
from sqlparse.tokens import Keyword, DML, Wildcard


TABELA_PERMITIDA = "funcionarios"
COLUNAS_PUBLICAS = {"id", "nome", "cargo"}
COLUNAS_RESTRITAS = {"cpf", "email_corporativo", "salario", "historico_medico"}
COLUNAS_ALTO_SIGILO = {"historico_medico"}  
COLUNAS_COM_EXCECAO_AGREGADA = {"salario"}  

PALAVRAS_CHAVE_PROIBIDAS = {
    "insert", "update", "delete", "drop", "alter", "attach", "detach",
    "pragma", "create", "replace", "vacuum", "reindex", "grant", "revoke",
}


# CAMADA 1 — Sanitização de input 

PADROES_INJECAO = [
    r"ignore\s+(todas\s+)?as?\s+instru[cç][õo]es",
    r"desconsidere\s+(as\s+)?(orienta[cç][õo]es|instru[cç][õo]es|regras)",
    r"modo\s+(desenvolvedor|debug|admin|irrestrito|sem\s+filtro)",
    r"voc[eê]\s+(agora\s+)?[eé]\s+um\s+assistente\s+sem\s+restri[cç][õo]es",
    r"a\s+partir\s+de\s+agora.{0,40}(sem|nenhum[a]?)\s+(restri|limita|filtro)",
    r"n[aã]o\s+h[aá]\s+mais\s+(limita[cç][ãa]o|restri[cç][ãa]o)",
]


def sanitizar_input(texto: str):
    for padrao in PADROES_INJECAO:
        if re.search(padrao, texto, re.IGNORECASE):
            return texto, True, f"Padrão suspeito detectado: '{padrao}'"
    return texto, False, None



# CAMADA 2 — Validação estrutural do SQL gerado 

def _extrair_colunas_select(statement):
    """Extrai os nomes de coluna pedidos no SELECT. Retorna None se for
    um SELECT * ou se não conseguir parsear com segurança (nesse caso,
    trate como 'pediu tudo', ou seja, o cenário mais restritivo)."""
    colunas = []
    select_seen = False
    for token in statement.tokens:
        if token.ttype is DML and token.value.upper() == "SELECT":
            select_seen = True
            continue
        if select_seen:
            if token.ttype is Keyword and token.value.upper() == "FROM":
                break
            if isinstance(token, IdentifierList):
                for ident in token.get_identifiers():
                    colunas.append(ident.get_real_name() or str(ident))
            elif isinstance(token, Identifier):
                colunas.append(token.get_real_name() or str(token))
            elif token.ttype is Wildcard:
                return None  # SELECT * — trata como "pediu todas as colunas"
    return [c.strip().lower() for c in colunas if c and c.strip()]


def validar_sql(query_sql: str):
    """
    Retorna (valido: bool, motivo: str|None, colunas_pedidas: list|None).

    Regras de allowlist :
    - Exatamente um statement.
    - Deve ser um SELECT (nenhum outro comando é aceito).
    - Nenhuma palavra-chave da lista de proibidas em nenhum lugar da query.
    - Só pode referenciar a tabela permitida (funcionarios).
    """
    if not query_sql or not query_sql.strip():
        return False, "Query vazia.", None

    statements = sqlparse.parse(query_sql)
    if len(statements) != 1:
        return False, f"Esperado 1 statement, recebido {len(statements)} (possível stacked query).", None

    stmt = statements[0]
    tipo = stmt.get_type()
    if tipo != "SELECT":
        return False, f"Apenas SELECT é permitido; comando detectado: {tipo}.", None

    texto_lower = query_sql.lower()
    for palavra in PALAVRAS_CHAVE_PROIBIDAS:
        if re.search(rf"\b{palavra}\b", texto_lower):
            return False, f"Palavra-chave proibida encontrada: '{palavra}'.", None

    # Verifica a tabela referenciada
    tabelas = [t.value.lower() for t in stmt.tokens if t.ttype is None and TABELA_PERMITIDA in t.value.lower()]
    if TABELA_PERMITIDA not in texto_lower:
        return False, f"Query não referencia a tabela permitida ('{TABELA_PERMITIDA}').", None
    # Bloqueia qualquer OUTRA tabela/objeto além da permitida
    outras_tabelas = re.findall(r"\b(?:from|join)\s+([a-zA-Z_][a-zA-Z0-9_]*)", texto_lower)
    for t in outras_tabelas:
        if t != TABELA_PERMITIDA:
            return False, f"Query referencia tabela não permitida: '{t}'.", None

    colunas_pedidas = _extrair_colunas_select(stmt)
    return True, None, colunas_pedidas


# CAMADA 3 — Least privilege a nível de coluna

_PADRAO_COLUNA_AGREGADA = re.compile(r"^(avg|sum|min|max|count)\((\w+)\)$")


def _nome_base_coluna(nome_coluna: str):
    """
    Dado um nome de coluna retornado pelo SQLite, identifica a coluna
    "real" por trás dele — por exemplo 'AVG(salario)' -> 'salario'.
    Retorna (nome_base, eh_agregado: bool).

    Isso corrige um bug real: comparar 'col.lower() in COLUNAS_RESTRITAS'
    por igualdade exata NUNCA bate contra 'AVG(salario)', porque o
    SQLite nomeia o resultado de uma agregação com a expressão inteira,
    não com o nome da coluna. Sem essa normalização, qualquer agregação
    sobre uma coluna restrita bypassa a Camada 3 inteira.
    """
    nome_lower = nome_coluna.lower().strip()
    m = _PADRAO_COLUNA_AGREGADA.match(nome_lower)
    if m:
        return m.group(2), True
    return nome_lower, False


def aplicar_least_privilege_colunas(colunas: list, linhas: list, colunas_pedidas):
    """
    Remove colunas restritas do resultado, mesmo que a query as tenha
    pedido — INCLUSIVE quando a coluna restrita aparece dentro de uma
    agregação (AVG/SUM/MIN/MAX), que antes bypassava essa checagem.

    Exceção: se a coluna restrita está em COLUNAS_COM_EXCECAO_AGREGADA
    E a ocorrência é agregada (não um valor individual), ela NÃO é
    removida aqui — fica marcada em 'colunas_para_dp' para a Camada 5
    aplicar ruído antes de seguir adiante. Isso nunca vale para colunas
    em COLUNAS_ALTO_SIGILO, que são sempre removidas, agregadas ou não.

    Retorna (colunas_filtradas, linhas_filtradas, colunas_removidas,
    indices_para_dp) — o último é a lista de índices (na lista já
    filtrada) que contêm um valor agregado de coluna sensível e
    precisam passar pela Camada 5 antes de chegar ao modelo.
    """
    indices_permitidos = []
    indices_para_dp_originais = []

    for i, col in enumerate(colunas):
        nome_base, eh_agregado = _nome_base_coluna(col)

        if nome_base not in COLUNAS_RESTRITAS:
            indices_permitidos.append(i)
            continue

        if nome_base in COLUNAS_ALTO_SIGILO:
            continue  # nunca passa, nem agregado

        if eh_agregado and nome_base in COLUNAS_COM_EXCECAO_AGREGADA:
            indices_permitidos.append(i)
            indices_para_dp_originais.append(i)
            continue

        # Restrita, não-agregada (ou agregada sem exceção de política): remove.

    colunas_filtradas = [colunas[i] for i in indices_permitidos]
    linhas_filtradas = [
        tuple(linha[i] for i in indices_permitidos)
        for linha in linhas
    ]
    colunas_removidas = [
        c for c in colunas
        if _nome_base_coluna(c)[0] in COLUNAS_RESTRITAS
        and c not in colunas_filtradas
    ]
    # Reindexa os índices de DP para a posição deles na lista JÁ FILTRADA
    indices_para_dp = [indices_permitidos.index(i) for i in indices_para_dp_originais]

    return colunas_filtradas, linhas_filtradas, colunas_removidas, indices_para_dp


# CAMADA 4 — Output filtering 

PADROES_DADO_SENSIVEL = [
    (r"\d{3}\.\d{3}\.\d{3}-\d{2}", "CPF formatado"),
    (r"[\w.\-]+@[\w.\-]+\.\w+", "e-mail"),
    (r"R\$\s?\d{1,3}(\.\d{3})*(,\d{2})?", "valor monetário (R$)"),
    (r"\b\d{1,3}(\.\d{3})*,\d{2}\b", "valor monetário (formato BR, sem R$)"),
    (r"\b\d+\.\d{2}\b", "valor numérico com 2 casas decimais (possível valor monetário)"),
]


def filtrar_output(texto: str):
    achou = []
    texto_filtrado = texto
    for padrao, descricao in PADROES_DADO_SENSIVEL:
        if re.search(padrao, texto_filtrado):
            achou.append(descricao)
            texto_filtrado = re.sub(padrao, "[DADO REMOVIDO PELO GUARDRAIL]", texto_filtrado)
    return texto_filtrado, achou



# CAMADA 5 — Privacidade diferencial para agregações sobre salário

def query_e_agregacao_salario(query_sql: str) -> bool:
    return bool(re.search(r"\b(avg|sum|max|min)\s*\(\s*salario\s*\)", query_sql, re.IGNORECASE))


def adicionar_ruido_laplace(valor: float, sensibilidade: float = 1000.0, epsilon: float = 1.0) -> float:
    """Ruído de Laplace calibrado por sensibilidade/epsilon (Dwork et al., 2006)."""
    import math
    escala = sensibilidade / epsilon
    u = random.random() - 0.5
    ruido = -escala * math.copysign(1, u) * math.log(1 - 2 * abs(u))
    return round(valor + ruido, 2)


def aplicar_privacidade_diferencial(linhas: list, indices_para_dp: list,
                                     sensibilidade: float = 1000.0, epsilon: float = 1.0):
    if not indices_para_dp:
        return linhas, False

    linhas_com_ruido = []
    for linha in linhas:
        linha = list(linha)
        for i in indices_para_dp:
            if isinstance(linha[i], (int, float)):
                linha[i] = adicionar_ruido_laplace(linha[i], sensibilidade, epsilon)
        linhas_com_ruido.append(tuple(linha))
    return linhas_com_ruido, True
