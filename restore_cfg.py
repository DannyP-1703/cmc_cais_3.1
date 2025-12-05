import json
from dataclasses import dataclass
import sys
from queue import Queue


@dataclass
class Tracepoint:
    address: int
    hexdump: str
    text: str
    is_branch: bool = False
    is_foreign_branch: bool = False
    foreign_target_address: int = -1
    foreign_target_name: str = ""

    @staticmethod
    def from_json(data: dict) -> "Tracepoint":
        return Tracepoint(
            address=data["address"],
            hexdump=data["hexDump"],
            text=data["text"],
            is_branch=data.get("isBranch", False),
            is_foreign_branch=data.get("isForeignBranch", False),
            foreign_target_address=data.get("foreignTargetAddress", -1),
            foreign_target_name=data.get("foreignTargetName", ""),
        )


def load_trace(file_path: str) -> list[Tracepoint]:
    with open(file_path, "r") as f:
        data = json.load(f)
    return [Tracepoint.from_json(tp) for tp in data]


class BB:
    def __init__(
        self,
        start_address: int,
        size: int,
        label: str = "",
    ):
        self.start_address = start_address
        self.size = size
        self.__label = label
        self.succs: list[BB] = []

    def __contains__(self, address: int) -> bool:
        return self.start_address <= address < self.start_address + self.size

    @property
    def label(self) -> str:
        if self.__label:
            return self.__label
        return f"{self.start_address:016X}"

    def __repr__(self):
        return self.label


def make_edge(bb_from: BB, bb_to: BB):
    if not any(succ.start_address == bb_to.start_address for succ in bb_from.succs):
        bb_from.succs.append(bb_to)


def get_labels(tracepoints: list[Tracepoint]) -> set[int]:
    labels: set[int] = set([tracepoints[0].address])
    for i, tp in enumerate(tracepoints):
        if tp.is_branch and i + 1 < len(tracepoints):
            labels.add(tracepoints[i + 1].address)
    return labels


def restore_cfg(tracepoints: list[Tracepoint], labels: set[int]) -> dict[int, BB]:
    B: BB = None
    B_prev: BB = None
    cfg: dict[int, BB] = {}
    start_tp_idx: int = 0
    tp_indx: int = start_tp_idx
    trace_len = len(tracepoints)

    while tp_indx < trace_len:
        tp = tracepoints[tp_indx]

        # bb ends on branch or when next tp is labeled
        if not tp.is_branch and tp_indx + 1 < trace_len and tracepoints[tp_indx + 1].address not in labels:
            tp_indx += 1
            continue

        start_address = tracepoints[start_tp_idx].address
        end_address = tp.address + len(bytes.fromhex(tp.hexdump))
        B = BB(start_address, end_address - start_address)
        cfg[B.start_address] = B

        if B_prev is not None:
            make_edge(B_prev, B)

        B_prev = B
        tp_indx += 1
        start_tp_idx = tp_indx

        # skip known bbs and manage foreign branches
        while True:

            # check if bb jums to a foreign target
            tp = tracepoints[start_tp_idx - 1]
            if tp.is_foreign_branch:
                if tp.foreign_target_address in cfg:
                    B = cfg[tp.foreign_target_address]
                else:
                    B = BB(tp.foreign_target_address, 0, label=tp.foreign_target_name)
                    cfg[B.start_address] = B
                make_edge(B_prev, B)
                B_prev = B

            if tp_indx >= trace_len:
                break

            tp = tracepoints[start_tp_idx]
            if tp.address in cfg:
                B = cfg[tp.address]
            else:
                break
            
            make_edge(B_prev, B)
            while tp_indx < trace_len and tracepoints[tp_indx].address in B:        # skip tps inside the known bb
                tp_indx += 1
            start_tp_idx = tp_indx
            B_prev = B

    return cfg


def dump_cfg(cfg: dict[int, BB], entry_addr: int) -> str:
    edges: list[str] = []
    visited = set()
    q = Queue()
    q.put(cfg[entry_addr])
    while not q.empty():
        bb: BB = q.get()
        if bb.start_address in visited:
            continue
        visited.add(bb.start_address)
        edges.extend([f'"{bb.label}" -> "{succ.label}";' for succ in bb.succs])
        for succ in bb.succs:
            if succ.start_address not in visited:
                q.put(succ)
    return "strict digraph {\n" + "\n".join(edges) + "\n}"


if __name__ == "__main__":
    assert len(sys.argv) == 3, (
        "Usage: python3 restore_cfg.py <trace_filename> <graph_filename>"
    )
    trace_filename = sys.argv[1]
    graph_filename = sys.argv[2]
    tracepoints = load_trace(trace_filename)
    labels = get_labels(tracepoints)
    cfg = restore_cfg(tracepoints, labels)
    dot_output = dump_cfg(cfg, tracepoints[0].address)
    with open(graph_filename, "w") as f:
        f.write(dot_output)
