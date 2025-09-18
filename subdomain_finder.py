import shutil
import subprocess
import sys
import time
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------- util ----------
def which(bin_name: str) -> str | None:
    return shutil.which(bin_name)

def run(cmd: list[str], timeout: int = 180, verbose: bool = False) -> tuple[int, str, str]:
    if verbose:
        print(f"[*] Exec: {' '.join(cmd)}")
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout ({timeout}s)"

def banner():
    print(r"""
 ________  ________  ________  ________  ________  _______   ________  ________  ________      
|\   ___ \|\   __  \|\   ____\|\   ____\|\   __  \|\  ___ \ |\   ____\|\   __  \|\   ___  \    
\ \  \_|\ \ \  \|\  \ \  \___|\ \  \___|\ \  \|\  \ \   __/|\ \  \___|\ \  \|\  \ \  \\ \  \   
 \ \  \ \\ \ \  \\\  \ \  \  __\ \_____  \ \   _  _\ \  \_|/_\ \  \    \ \  \\\  \ \  \\ \  \  
  \ \  \_\\ \ \  \\\  \ \  \|\  \|____|\  \ \  \\  \\ \  \_|\ \ \  \____\ \  \\\  \ \  \\ \  \ 
   \ \_______\ \_______\ \_______\____\_\  \ \__\\ _\\ \_______\ \_______\ \_______\ \__\\ \__\
    \|_______|\|_______|\|_______|\_________\|__|\|__|\|_______|\|_______|\|_______|\|__| \|__|
                                 \|_________|                                                  
                                                                                               
                                                                                               
    """)
    print("                        subdomain recon - made by Ðogspløit.py")
    print()

def pick_httpx_bin() -> str | None:
    for b in ("httpx", "httpx-toolkit"):
        p = which(b)
        if p:
            return p
    return None

# ---------- etapas ----------
def run_subfinder(domain: str, out_file: Path, verbose: bool):
    binp = which("subfinder")
    if not binp:
        if verbose: print("[!] subfinder não encontrado, pulando.")
        return []
    cmd = [binp, "-d", domain, "-all", "-silent", "-o", str(out_file)]
    code, out, err = run(cmd, verbose=verbose)
    if code != 0 and verbose:
        print(f"[!] subfinder retornou {code}: {err.strip()}")
    lines = out_file.read_text(encoding="utf-8", errors="ignore").splitlines() if out_file.exists() else []
    return [l.strip() for l in lines if l.strip()]

def run_findomain(domain: str, tmp_dir: Path, verbose: bool):
    binp = which("findomain")
    if not binp:
        if verbose: print("[!] findomain não encontrado, pulando.")
        return []
    cwd = os.getcwd()
    try:
        os.chdir(tmp_dir)
        cmd = [binp, "--output", "-t", domain]
        code, out, err = run(cmd, verbose=verbose)
    finally:
        os.chdir(cwd)
    f = tmp_dir / f"{domain}.txt"
    lines = f.read_text(encoding="utf-8", errors="ignore").splitlines() if f.exists() else []
    return [l.strip() for l in lines if l.strip()]

def run_assetfinder(domain: str, out_file: Path, verbose: bool):
    binp = which("assetfinder")
    if not binp:
        if verbose: print("[!] assetfinder não encontrado, pulando.")
        return []
    cmd = [binp, "-subs-only", domain]
    code, out, err = run(cmd, verbose=verbose)
    if out:
        out_file.write_text(out, encoding="utf-8")
    elif err and verbose:
        print(f"[!] assetfinder: {err.strip()}")
    return [l.strip() for l in (out or "").splitlines() if l.strip()]

def run_amass(domain: str, out_file: Path, verbose: bool):
    binp = which("amass")
    if not binp:
        if verbose: print("[!] amass não encontrado, pulando.")
        return []
    cmd = [binp, "enum", "-d", domain, "-passive", "-silent"]
    code, out, err = run(cmd, timeout=420, verbose=verbose)
    if out:
        out_file.write_text(out, encoding="utf-8")
    elif err and verbose:
        print(f"[!] amass: {err.strip()}")
    return [l.strip() for l in (out or "").splitlines() if l.strip()]

def merge_and_write(files: list[Path], merged_file: Path) -> list[str]:
    items: set[str] = set()
    for f in files:
        if f and f.exists():
            for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                s = line.strip().lower()
                if s:
                    items.add(s)
    lst = sorted(items)
    merged_file.write_text("\n".join(lst), encoding="utf-8")
    return lst

def run_httpx(input_file: Path, output_file: Path, verbose: bool):
    binp = pick_httpx_bin()
    if not binp:
        if verbose: print("[!] httpx/httpx-toolkit não encontrado; pulando validação HTTP.")
        return []
    cmd = [binp, "-l", str(input_file), "-sc", "-title", "-td", "-mc", "200,302,403,401", "-o", str(output_file)]
    code, out, err = run(cmd, timeout=420, verbose=verbose)
    if code != 0 and verbose:
        print(f"[!] httpx retornou {code}: {err.strip()}")
    lines = output_file.read_text(encoding="utf-8", errors="ignore").splitlines() if output_file.exists() else []
    return lines

# ---------- coleta paralela ----------
def collect_parallel(domain: str, tmp: Path, verbose: bool,
                     subfinder_out: Path, assetfinder_out: Path, amass_out: Path):
    """
    Executa subfinder, findomain, assetfinder e amass em paralelo.
    Mantém a mesma base/arquitetura, apenas paralelizando as etapas de coleta.
    """
    tasks = {}

    def submit_if_available(exe, name, fn, *args):
        # mensagem "início" (mantendo o estilo original)
        if name == "subfinder":
            print(f"\n\033[1;34mColetando subdomínios com subfinder...\033[0m")
        elif name == "findomain":
            print(f"\n\033[1;34mColetando subdomínios com findomain...\033[0m")
        elif name == "assetfinder":
            print(f"\n\033[1;34mColetando subdomínios com assetfinder...\033[0m")
        elif name == "amass":
            print(f"\n\033[1;34mColetando subdomínios com amass...\033[0m")

        fut = exe.submit(fn, *args)
        tasks[fut] = name

    results: dict[str, list[str]] = {
        "subfinder": [],
        "findomain": [],
        "assetfinder": [],
        "amass": []
    }

    with ThreadPoolExecutor(max_workers=4) as exe:
        submit_if_available(exe, "subfinder", run_subfinder, domain, subfinder_out, verbose)
        submit_if_available(exe, "findomain", run_findomain, domain, tmp, verbose)
        submit_if_available(exe, "assetfinder", run_assetfinder, domain, assetfinder_out, verbose)
        submit_if_available(exe, "amass", run_amass, domain, amass_out, verbose)

        for fut in as_completed(tasks):
            name = tasks[fut]
            try:
                data = fut.result() or []
            except Exception as e:
                if verbose:
                    print(f"[!] {name} falhou: {e}")
                data = []
            results[name] = data
            if verbose:
                print(f"[+] {name} finalizado — {len(data)} linhas")

    return results

# ---------- main (interativo) ----------
def main():
    banner()

    # entrada interativa
    domain = input("Domínio alvo (ex: example.com): ").strip()
    if not domain or "." not in domain:
        print("[!] Forneça um domínio válido, ex: example.com")
        sys.exit(1)

    verbose_ans = input("Modo verbose? (y/N): ").strip().lower()
    verbose = verbose_ans in ("y", "yes", "s", "sim")

    # paths
    work = Path.cwd()
    tmp = work / f".dogsploit_{int(time.time())}"
    tmp.mkdir(parents=True, exist_ok=True)

    subfinder_out = tmp / f"subfinder-{domain}.txt"
    assetfinder_out = tmp / f"assetfinder-{domain}.txt"
    amass_out = tmp / f"amass-{domain}.txt"
    merged = tmp / f"subdomains-{domain}.txt"
    httpx_out = work / f"{domain}-subs.txt"

    # 1) coleta (AGORA EM PARALELO)
    results = collect_parallel(
        domain=domain,
        tmp=tmp,
        verbose=verbose,
        subfinder_out=subfinder_out,
        assetfinder_out=assetfinder_out,
        amass_out=amass_out
    )

    # 2) merge
    print(f"\n\033[1;34mUnificando resultados...\033[0m")
    merged_list = merge_and_write(
        [subfinder_out, assetfinder_out, amass_out, tmp / f"{domain}.txt"],  # findomain escreve <domain>.txt
        merged
    )
    print(f"[+] Total bruto único: {len(merged_list)}")

    # 3) valida http com httpx
    print(f"\n\033[1;34mValidando com httpx (200,302,403,401)...\033[0m")
    _ = run_httpx(merged, httpx_out, verbose)

    print(f"\n\033[1;32mTodos os subdomínios foram processados!\033[0m")
    if httpx_out.exists():
        print(f"[+] Saída final: {httpx_out}")

    # prompts (iguais ao fluxo da versão bash)
    try:
        resp1 = input(f"\nMostrar total de subdomínios válidos? (Y/n) ").strip().lower()
        if resp1 in ("", "y", "yes", "s", "sim"):
            if httpx_out.exists():
                with open(httpx_out, "r", encoding="utf-8", errors="ignore") as f:
                    total_valid = sum(1 for _ in f)
                print(f"\033[1;33mTotal de válidos:\033[0m {total_valid}")
            else:
                print("[-] httpx não gerou arquivo de saída.")

        resp2 = input(f"\nExibir a lista no terminal? (Y/n) ").strip().lower()
        if resp2 in ("", "y", "yes", "s", "sim"):
            if httpx_out.exists():
                print()
                print(Path(httpx_out).read_text(encoding="utf-8", errors="ignore"))
            else:
                print("[-] httpx não gerou arquivo de saída.")

        # manter a lógica de salvar em diretório escolhido
        resp_save = input(f"\nSalvar o arquivo final em algum diretório? (y/N) ").strip().lower()
        if resp_save in ("y", "yes", "s", "sim"):
            dest_dir = input("Informe o diretório de destino (ex: /tmp ou C:\\temp): ").strip()
            if dest_dir:
                dest_path = Path(dest_dir).expanduser().resolve()
                try:
                    dest_path.mkdir(parents=True, exist_ok=True)
                    dest_file = dest_path / httpx_out.name
                    shutil.copy2(httpx_out, dest_file)
                    print(f"[+] Copiado para: {dest_file}")
                except Exception as e:
                    print(f"[!] Falha ao salvar no diretório informado: {e}")
            else:
                print("[!] Diretório não informado, mantendo no diretório atual.")

        resp3 = input(f"\nRemover arquivos intermediários? (Y/n) ").strip().lower()
        if resp3 in ("", "y", "yes", "s", "sim"):
            try:
                shutil.rmtree(tmp, ignore_errors=True)
                print(f"\033[1;33mArquivos temporários removidos.\033[0m")
            except Exception as e:
                print(f"[!] Falha ao limpar temporários: {e}")
        else:
            print(f"[i] Mantidos em: {tmp}")

    except KeyboardInterrupt:
        print("\n[!] Encerrado pelo usuário.")

if __name__ == "__main__":
    main()
