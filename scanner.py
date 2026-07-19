#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Massive Port Scanner - Escáner de puertos ultrarrápido en Python
Uso: python scanner.py -t <IP> -p <NÚMERO_DE_PUERTOS> -o <ARCHIVO_SALIDA>
"""

import asyncio
import socket
import argparse
import json
import csv
import sys
from datetime import datetime
from ipaddress import ip_network, ip_address

# Lista de los 10,000 puertos más comunes (Top 1000 por ahora para no saturar)
# Puedes expandir esta lista o generar los 10,000
COMMON_PORTS = [
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 382, 383, 384, 385, 386, 387, 388, 389, 390, 391, 392, 393, 394, 395, 396, 397, 398, 399, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482, 483, 484, 485, 486, 487, 488, 489, 490, 491, 492, 493, 494, 495, 496, 497, 498, 499, 500, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 518, 519, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 538, 539, 540, 541, 542, 543, 544, 545, 546, 547, 548, 549, 550, 551, 552, 553, 554, 555, 556, 557, 558, 559, 560, 561, 562, 563, 564, 565, 566, 567, 568, 569, 570, 571, 572, 573, 574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 585, 586, 587, 588, 589, 590, 591, 592, 593, 594, 595, 596, 597, 598, 599, 600, 601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611, 612, 613, 614, 615, 616, 617, 618, 619, 620, 621, 622, 623, 624, 625, 626, 627, 628, 629, 630, 631, 632, 633, 634, 635, 636, 637, 638, 639, 640, 641, 642, 643, 644, 645, 646, 647, 648, 649, 650, 651, 652, 653, 654, 655, 656, 657, 658, 659, 660, 661, 662, 663, 664, 665, 666, 667, 668, 669, 670, 671, 672, 673, 674, 675, 676, 677, 678, 679, 680, 681, 682, 683, 684, 685, 686, 687, 688, 689, 690, 691, 692, 693, 694, 695, 696, 697, 698, 699, 700, 701, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712, 713, 714, 715, 716, 717, 718, 719, 720, 721, 722, 723, 724, 725, 726, 727, 728, 729, 730, 731, 732, 733, 734, 735, 736, 737, 738, 739, 740, 741, 742, 743, 744, 745, 746, 747, 748, 749, 750, 751, 752, 753, 754, 755, 756, 757, 758, 759, 760, 761, 762, 763, 764, 765, 766, 767, 768, 769, 770, 771, 772, 773, 774, 775, 776, 777, 778, 779, 780, 781, 782, 783, 784, 785, 786, 787, 788, 789, 790, 791, 792, 793, 794, 795, 796, 797, 798, 799, 800, 801, 802, 803, 804, 805, 806, 807, 808, 809, 810, 811, 812, 813, 814, 815, 816, 817, 818, 819, 820, 821, 822, 823, 824, 825, 826, 827, 828, 829, 830, 831, 832, 833, 834, 835, 836, 837, 838, 839, 840, 841, 842, 843, 844, 845, 846, 847, 848, 849, 850, 851, 852, 853, 854, 855, 856, 857, 858, 859, 860, 861, 862, 863, 864, 865, 866, 867, 868, 869, 870, 871, 872, 873, 874, 875, 876, 877, 878, 879, 880, 881, 882, 883, 884, 885, 886, 887, 888, 889, 890, 891, 892, 893, 894, 895, 896, 897, 898, 899, 900, 901, 902, 903, 904, 905, 906, 907, 908, 909, 910, 911, 912, 913, 914, 915, 916, 917, 918, 919, 920, 921, 922, 923, 924, 925, 926, 927, 928, 929, 930, 931, 932, 933, 934, 935, 936, 937, 938, 939, 940, 941, 942, 943, 944, 945, 946, 947, 948, 949, 950, 951, 952, 953, 954, 955, 956, 957, 958, 959, 960, 961, 962, 963, 964, 965, 966, 967, 968, 969, 970, 971, 972, 973, 974, 975, 976, 977, 978, 979, 980, 981, 982, 983, 984, 985, 986, 987, 988, 989, 990, 991, 992, 993, 994, 995, 996, 997, 998, 999, 1000
] # Lista truncada para el ejemplo, pero tú puedes usar una lista completa de 10,000 puertos

async def scan_port(ip, port, timeout=2):
    """Intenta conectar a un puerto específico de forma asíncrona."""
    try:
        # Usamos asyncio.open_connection para conexiones no bloqueantes
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port, True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError, socket.gaierror):
        return port, False
    except Exception:
        return port, False

async def scan_ports(ip, ports, timeout=2, concurrency=500):
    """
    Controla la concurrencia máxima para no saturar el sistema.
    Escanea una lista de puertos en una IP dada.
    """
    semaphore = asyncio.Semaphore(concurrency)
    
    async def limited_scan(p):
        async with semaphore:
            return await scan_port(ip, p, timeout)
    
    tasks = [limited_scan(p) for p in ports]
    results = await asyncio.gather(*tasks)
    
    open_ports = [p for p, is_open in results if is_open]
    return open_ports

def expand_ip_targets(target_str):
    """
    Expande una cadena de destino que puede ser:
    - Una IP única: '192.168.1.1'
    - Un rango CIDR: '192.168.1.0/24'
    - Un archivo con lista de IPs: 'ips.txt'
    """
    if target_str.endswith('.txt'):
        try:
            with open(target_str, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
            return ips
        except FileNotFoundError:
            print(f"[!] Archivo '{target_str}' no encontrado.")
            sys.exit(1)
    elif '/' in target_str:
        try:
            network = ip_network(target_str, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            print(f"[!] Rango CIDR '{target_str}' inválido.")
            sys.exit(1)
    else:
        try:
            ip_address(target_str)
            return [target_str]
        except ValueError:
            print(f"[!] IP '{target_str}' inválida.")
            sys.exit(1)

def save_results(ip, open_ports, output_file, format='json'):
    """Guarda los resultados en formato JSON o CSV."""
    data = {
        "target": ip,
        "scan_date": datetime.now().isoformat(),
        "open_ports": open_ports,
        "total_open": len(open_ports)
    }
    
    try:
        if format == 'json':
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=4)
        elif format == 'csv':
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['IP', 'Puerto'])
                for port in open_ports:
                    writer.writerow([ip, port])
        print(f"[+] Resultados guardados en '{output_file}'")
    except Exception as e:
        print(f"[!] Error al guardar archivo: {e}")

async def main():
    parser = argparse.ArgumentParser(description="Massive Port Scanner - Escáner ultrarrápido de puertos")
    parser.add_argument("-t", "--target", required=True, help="IP, rango CIDR (ej. 192.168.1.0/24) o archivo .txt con lista de IPs")
    parser.add_argument("-p", "--ports", type=int, default=1000, help="Número de puertos a escanear (usa los más comunes). Por defecto: 1000")
    parser.add_argument("--timeout", type=float, default=1.5, help="Tiempo de espera por puerto en segundos. Por defecto: 1.5")
    parser.add_argument("--concurrency", type=int, default=500, help="Nivel de concurrencia (máximo de tareas simultáneas). Por defecto: 500")
    parser.add_argument("-o", "--output", help="Archivo de salida para guardar los resultados")
    parser.add_argument("--format", choices=['json', 'csv'], default='json', help="Formato de salida: json o csv. Por defecto: json")
    
    args = parser.parse_args()
    
    # Determinar lista de puertos
    if args.ports > len(COMMON_PORTS):
        print(f"[!] Solo hay {len(COMMON_PORTS)} puertos en la lista predefinida. Usando todos.")
        ports_to_scan = COMMON_PORTS
    else:
        ports_to_scan = COMMON_PORTS[:args.ports]
    
    print(f"[*] Iniciando escaneo en {args.target}")
    print(f"[*] Puertos a escanear: {len(ports_to_scan)}")
    print(f"[*] Timeout: {args.timeout}s | Concurrencia: {args.concurrency}")
    
    # Expandir el objetivo (IPs a escanear)
    targets = expand_ip_targets(args.target)
    print(f"[*] Objetivos a escanear: {len(targets)}")
    
    for target_ip in targets:
        print(f"\n[*] Escaneando {target_ip}...")
        open_ports = await scan_ports(target_ip, ports_to_scan, args.timeout, args.concurrency)
        
        if open_ports:
            print(f"[+] Puertos abiertos en {target_ip}: {len(open_ports)}")
            print(f"    {', '.join(map(str, open_ports[:20]))}" + ("..." if len(open_ports) > 20 else ""))
        else:
            print(f"[-] No se encontraron puertos abiertos en {target_ip}")
        
        # Guardar resultados si se especificó archivo de salida
        if args.output:
            # Si hay múltiples IPs, añadir la IP al nombre del archivo para no sobrescribir
            if len(targets) > 1:
                base, ext = args.output.rsplit('.', 1) if '.' in args.output else (args.output, '')
                output_file = f"{base}_{target_ip}.{ext}" if ext else f"{base}_{target_ip}"
            else:
                output_file = args.output
            save_results(target_ip, open_ports, output_file, args.format)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Escaneo interrumpido por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error inesperado: {e}")
        sys.exit(1)
