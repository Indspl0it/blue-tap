#!/usr/bin/env python3
"""Generate canned data for the Vulnerable IVI Simulator.

Creates phonebook contacts, call history, SMS messages, MAP listing XMLs,
and AT command response files — all from a deterministic seed so the data
is reproducible across runs.

Usage:
    python3 gen_data.py                     # defaults: 50 contacts, 20 messages
    python3 gen_data.py --seed 99           # different seed
    python3 gen_data.py --clean             # delete existing, regenerate
    python3 gen_data.py --contacts 100      # more contacts
"""

import argparse
import os
import random
import shutil
import sys
from datetime import datetime, timedelta

# ── Name pools ─────────────────────────────────────────────────────────────

FIRST_NAMES = [
    "John", "Maria", "Wei", "Aisha", "James", "Sofia", "Raj", "Elena",
    "Carlos", "Yuki", "David", "Fatima", "Michael", "Priya", "Robert",
    "Lin", "Ahmed", "Sarah", "Omar", "Hannah", "Chen", "Isabella",
    "Dmitri", "Amara", "Thomas", "Mei", "Hassan", "Emma", "Jorge",
    "Sakura", "William", "Nadia", "Kevin", "Zara", "Daniel", "Ananya",
    "Marcus", "Leila", "Patrick", "Soo-Jin", "Nathan", "Ines", "Ryan",
    "Olga", "Brian", "Chloe", "Tariq", "Freya", "Sean", "Rosa",
]

LAST_NAMES = [
    "Smith", "Garcia", "Chen", "Patel", "Johnson", "Kim", "Williams",
    "Müller", "Brown", "Singh", "Jones", "Lopez", "Wilson", "Tanaka",
    "Davis", "Ali", "Anderson", "Santos", "Taylor", "Nguyen", "Thomas",
    "Park", "Martinez", "Johansson", "Jackson", "Ivanov", "White",
    "Nakamura", "Harris", "Okafor", "Martin", "Gupta", "Thompson",
    "Suzuki", "Robinson", "Fernandez", "Clark", "Das", "Lewis", "Costa",
    "Walker", "Petrov", "Hall", "Schmidt", "Young", "Rossi", "King",
    "Berg", "Scott", "Sato",
]

AREA_CODES = ["415", "650", "408", "510", "925", "707", "831"]

STREETS = [
    "Main St", "Oak Ave", "Elm Dr", "Cedar Ln", "Pine Rd", "Maple Ct",
    "Park Blvd", "Lake Dr", "Hill Rd", "Valley Way", "River Rd", "Spring St",
    "Forest Ave", "Sunset Blvd", "Harbor Dr", "Vista Ln", "Sierra Way",
]

CITIES_STATES = [
    ("Springfield", "IL", "62701"), ("San Jose", "CA", "95101"),
    ("Portland", "OR", "97201"), ("Austin", "TX", "78701"),
    ("Denver", "CO", "80201"), ("Seattle", "WA", "98101"),
    ("Boston", "MA", "02101"), ("Miami", "FL", "33101"),
    ("Phoenix", "AZ", "85001"), ("Atlanta", "GA", "30301"),
]

EMAIL_DOMAINS = ["gmail.com", "outlook.com", "yahoo.com", "example.com", "icloud.com"]

SMS_BODIES = [
    "Hey, are you picking up the kids today?",
    "Running 10 min late, sorry!",
    "Can you grab milk on the way home?",
    "Meeting moved to 3pm",
    "Happy birthday! Hope you have a great day",
    "The car is making that noise again",
    "Dinner reservation at 7 tonight",
    "Did you see the game last night?",
    "Flight lands at 6:45pm gate B12",
    "Don't forget the dentist appointment tomorrow",
    "Just left the office, be there in 20",
    "Can we reschedule to Thursday?",
    "Package delivered - left at front door",
    "Thanks for lunch, it was great catching up",
    "The wifi password is BlueTooth2026",
    "Pick up my prescription please? CVS on Main St",
    "Board meeting pushed to next week",
    "Kids have soccer practice at 4",
    "Oil change reminder - 3000 miles overdue",
    "Love you, drive safe",
]


# ── Data structures ────────────────────────────────────────────────────────

class Contact:
    def __init__(self, index, first, last, cell, work, email, address):
        self.index = index
        self.first = first
        self.last = last
        self.cell = cell
        self.work = work      # may be None
        self.email = email    # may be None
        self.address = address  # may be None (tuple or None)


class CallEntry:
    def __init__(self, name, number, call_type, timestamp):
        self.name = name
        self.number = number
        self.call_type = call_type  # RECEIVED, DIALED, MISSED
        self.timestamp = timestamp

    @property
    def timestamp_str(self):
        return self.timestamp.strftime("%Y%m%dT%H%M%S")


class Message:
    def __init__(self, handle, sender_name, sender_number, body, folder,
                 status, timestamp):
        self.handle = handle
        self.sender_name = sender_name
        self.sender_number = sender_number
        self.body = body
        self.folder = folder
        self.status = status  # READ or UNREAD
        self.timestamp = timestamp

    @property
    def handle_str(self):
        return f"{self.handle:04d}"

    @property
    def datetime_str(self):
        return self.timestamp.strftime("%Y%m%dT%H%M%S")

    @property
    def cmgl_date_str(self):
        return self.timestamp.strftime("%y/%m/%d,%H:%M:%S+00")


# ── Generators ─────────────────────────────────────────────────────────────

def gen_phone_number():
    area = random.choice(AREA_CODES)
    return f"+1{area}{random.randint(1000000, 9999999)}"


def gen_contacts(count):
    max_unique = len(FIRST_NAMES) * len(LAST_NAMES)
    if count > max_unique:
        print(f"[!] Warning: requested {count} contacts but only {max_unique} "
              f"unique name combinations available. Capping at {max_unique}.")
        count = max_unique

    contacts = []
    used_names = set()
    for i in range(1, count + 1):
        while True:
            first = random.choice(FIRST_NAMES)
            last = random.choice(LAST_NAMES)
            if (first, last) not in used_names:
                used_names.add((first, last))
                break

        cell = gen_phone_number()
        work = gen_phone_number() if random.random() < 0.3 else None
        email = (f"{first.lower()}.{last.lower()}@{random.choice(EMAIL_DOMAINS)}"
                 if random.random() < 0.6 else None)
        address = None
        if random.random() < 0.4:
            num = random.randint(100, 9999)
            street = random.choice(STREETS)
            city, state, zipcode = random.choice(CITIES_STATES)
            address = (f"{num} {street}", city, state, zipcode)

        contacts.append(Contact(i, first, last, cell, work, email, address))
    return contacts


def gen_call_history(contacts, n_incoming, n_outgoing, n_missed):
    now = datetime.now()
    callers = random.sample(contacts, min(15, len(contacts)))
    # Add 5 unknown numbers
    unknown = [(f"Unknown {i}", gen_phone_number()) for i in range(1, 6)]

    entries = []
    all_callers = [(c.first + " " + c.last, c.cell) for c in callers] + unknown

    for _ in range(n_incoming):
        name, number = random.choice(all_callers)
        ts = now - timedelta(
            days=random.randint(0, 6),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
        )
        entries.append(CallEntry(name, number, "RECEIVED", ts))

    for _ in range(n_outgoing):
        name, number = random.choice(all_callers)
        ts = now - timedelta(
            days=random.randint(0, 6),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
        )
        entries.append(CallEntry(name, number, "DIALED", ts))

    for _ in range(n_missed):
        name, number = random.choice(all_callers)
        ts = now - timedelta(
            days=random.randint(0, 6),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
        )
        entries.append(CallEntry(name, number, "MISSED", ts))

    return entries


def gen_messages(contacts, bodies, total=20):
    messages = []
    senders = random.sample(contacts, min(12, len(contacts)))
    handle = 1

    # Distribute messages: 50% inbox, 25% sent, 15% draft, 10% deleted
    n_inbox = max(1, round(total * 0.50))
    n_sent = max(1, round(total * 0.25))
    n_draft = max(1, round(total * 0.15))
    n_deleted = total - n_inbox - n_sent - n_draft
    if n_deleted < 0:
        n_deleted = 0
        n_inbox = total - n_sent - n_draft

    # inbox (70% read, 30% unread)
    for i in range(n_inbox):
        c = random.choice(senders)
        status = "READ" if i < round(n_inbox * 0.7) else "UNREAD"
        ts = datetime.now() - timedelta(
            days=random.randint(0, 5),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
        )
        messages.append(Message(
            handle, f"{c.first} {c.last}", c.cell,
            bodies[(handle - 1) % len(bodies)], "inbox", status, ts,
        ))
        handle += 1

    # sent
    for i in range(n_sent):
        c = random.choice(senders)
        ts = datetime.now() - timedelta(
            days=random.randint(0, 5),
            hours=random.randint(0, 12),
        )
        messages.append(Message(
            handle, f"{c.first} {c.last}", c.cell,
            bodies[(handle - 1) % len(bodies)], "sent", "READ", ts,
        ))
        handle += 1

    # draft
    for i in range(n_draft):
        c = random.choice(senders)
        ts = datetime.now() - timedelta(hours=random.randint(1, 48))
        messages.append(Message(
            handle, f"{c.first} {c.last}", c.cell,
            bodies[(handle - 1) % len(bodies)], "draft", "READ", ts,
        ))
        handle += 1

    # deleted
    for i in range(n_deleted):
        c = random.choice(senders)
        ts = datetime.now() - timedelta(days=random.randint(3, 10))
        messages.append(Message(
            handle, f"{c.first} {c.last}", c.cell,
            bodies[(handle - 1) % len(bodies)], "deleted", "READ", ts,
        ))
        handle += 1

    return messages


# ── Formatters ─────────────────────────────────────────────────────────────

def format_vcard(contact):
    lines = [
        "BEGIN:VCARD",
        "VERSION:2.1",
        f"N:{contact.last};{contact.first};;;",
        f"FN:{contact.first} {contact.last}",
        f"TEL;CELL:{contact.cell}",
    ]
    if contact.work:
        lines.append(f"TEL;WORK:{contact.work}")
    if contact.email:
        lines.append(f"EMAIL:{contact.email}")
    if contact.address:
        street, city, state, zipcode = contact.address
        lines.append(f"ADR;HOME:;;{street};{city};{state};{zipcode};US")
    lines.append("END:VCARD")
    return "\r\n".join(lines)


def format_call_vcard(entry):
    lines = [
        "BEGIN:VCARD",
        "VERSION:2.1",
        f"N:{entry.name.split()[-1]};{entry.name.split()[0]}",
        f"FN:{entry.name}",
        f"TEL:{entry.number}",
        f"X-IRMC-CALL-DATETIME;{entry.call_type}:{entry.timestamp_str}",
        "END:VCARD",
    ]
    return "\r\n".join(lines)


def format_bmessage(msg):
    # MAP spec: LENGTH = byte length of entire BBODY content
    # (BEGIN:MSG\r\n + body + \r\nEND:MSG\r\n)
    msg_block = f"BEGIN:MSG\r\n{msg.body}\r\nEND:MSG"
    bbody_len = len(msg_block.encode("utf-8"))

    name_parts = msg.sender_name.split()
    last = name_parts[-1] if name_parts else ""
    first = name_parts[0] if name_parts else ""

    lines = [
        "BEGIN:BMSG",
        "VERSION:1.0",
        f"STATUS:{msg.status}",
        "TYPE:SMS_GSM",
        f"FOLDER:telecom/msg/{msg.folder}",
        "BEGIN:VCARD",
        "VERSION:2.1",
        f"FN:{msg.sender_name}",
        f"TEL:{msg.sender_number}",
        f"N:{last};{first}",
        "END:VCARD",
        "BEGIN:BENV",
        "BEGIN:BBODY",
        "CHARSET:UTF-8",
        f"LENGTH:{bbody_len}",
        "BEGIN:MSG",
        msg.body,
        "END:MSG",
        "END:BBODY",
        "END:BENV",
        "END:BMSG",
    ]
    return "\r\n".join(lines)


def format_msg_listing_xml(messages):
    lines = ['<?xml version="1.0"?>', '<MAP-msg-listing version="1.0">']
    for msg in messages:
        read = "yes" if msg.status == "READ" else "no"
        subject = (msg.body[:30]
                   .replace("&", "&amp;")
                   .replace('"', "&quot;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;"))
        lines.append(
            f'  <msg handle="{msg.handle_str}" subject="{subject}" '
            f'datetime="{msg.datetime_str}" sender_name="{msg.sender_name}" '
            f'sender_addressing="{msg.sender_number}" type="SMS_GSM" '
            f'size="{len(msg.body)}" reception_status="complete" read="{read}"/>'
        )
    lines.append("</MAP-msg-listing>")
    return "\n".join(lines)


def format_cpbr_entry(contact):
    number_type = 145 if contact.cell.startswith("+") else 129
    return f'+CPBR: {contact.index},"{contact.cell}",{number_type},"{contact.first} {contact.last}"'


def format_cmgl_entry(msg):
    stat = "REC UNREAD" if msg.status == "UNREAD" else "REC READ"
    return (
        f'+CMGL: {msg.handle},"{stat}","{msg.sender_number}"'
        f',,"{msg.cmgl_date_str}"\r\n{msg.body}'
    )


# ── File writers ───────────────────────────────────────────────────────────

def write_phonebook(contacts, output_dir):
    path = os.path.join(output_dir, "phonebook.vcf")
    with open(path, "w", newline="") as f:
        for i, c in enumerate(contacts):
            if i > 0:
                f.write("\r\n")
            f.write(format_vcard(c))
    return path


def write_call_history(entries, output_dir):
    incoming = [e for e in entries if e.call_type == "RECEIVED"]
    outgoing = [e for e in entries if e.call_type == "DIALED"]
    missed = [e for e in entries if e.call_type == "MISSED"]
    combined = sorted(entries, key=lambda e: e.timestamp, reverse=True)

    files = {
        "ich.vcf": incoming,
        "och.vcf": outgoing,
        "mch.vcf": missed,
        "cch.vcf": combined,
    }
    paths = []
    for filename, data in files.items():
        path = os.path.join(output_dir, filename)
        with open(path, "w", newline="") as f:
            for i, entry in enumerate(data):
                if i > 0:
                    f.write("\r\n")
                f.write(format_call_vcard(entry))
        paths.append(path)
    return paths


def write_messages(messages, output_dir):
    msg_dir = os.path.join(output_dir, "messages")
    paths = []
    for msg in messages:
        folder_dir = os.path.join(msg_dir, msg.folder)
        os.makedirs(folder_dir, exist_ok=True)
        path = os.path.join(folder_dir, f"{msg.handle_str}.bmsg")
        with open(path, "w", newline="") as f:
            f.write(format_bmessage(msg))
        paths.append(path)
    return paths


def write_msg_listings(messages, output_dir):
    msg_dir = os.path.join(output_dir, "messages")
    paths = []
    for folder in ["inbox", "sent", "draft", "deleted"]:
        folder_msgs = [m for m in messages if m.folder == folder]
        path = os.path.join(msg_dir, f"{folder}_listing.xml")
        with open(path, "w") as f:
            f.write(format_msg_listing_xml(folder_msgs))
        paths.append(path)
    return paths


def write_at_phonebook(contacts, output_dir):
    path = os.path.join(output_dir, "at_phonebook.txt")
    with open(path, "w") as f:
        for c in contacts:
            f.write(format_cpbr_entry(c) + "\n")
    return path


def write_at_sms(messages, output_dir):
    path = os.path.join(output_dir, "at_sms.txt")
    with open(path, "w") as f:
        for msg in messages:
            f.write(format_cmgl_entry(msg) + "\n")
    return path


# ── Validation ─────────────────────────────────────────────────────────────

def validate(output_dir, expected_contacts, expected_messages):
    errors = []

    # Phonebook
    pb_path = os.path.join(output_dir, "phonebook.vcf")
    if os.path.exists(pb_path):
        content = open(pb_path).read()
        count = content.count("BEGIN:VCARD")
        if count != expected_contacts:
            errors.append(f"phonebook.vcf: expected {expected_contacts} vCards, got {count}")
        # Check structure
        if content.count("BEGIN:VCARD") != content.count("END:VCARD"):
            errors.append("phonebook.vcf: mismatched BEGIN/END:VCARD")
    else:
        errors.append("phonebook.vcf: missing")

    # Call history
    for fname in ["ich.vcf", "och.vcf", "mch.vcf", "cch.vcf"]:
        fpath = os.path.join(output_dir, fname)
        if not os.path.exists(fpath):
            errors.append(f"{fname}: missing")
            continue
        content = open(fpath).read()
        if content.count("BEGIN:VCARD") != content.count("END:VCARD"):
            errors.append(f"{fname}: mismatched BEGIN/END:VCARD")
        if "X-IRMC-CALL-DATETIME" not in content and content.strip():
            errors.append(f"{fname}: missing X-IRMC-CALL-DATETIME")

    # Messages
    msg_dir = os.path.join(output_dir, "messages")
    total_msgs = 0
    for folder in ["inbox", "sent", "draft", "deleted"]:
        folder_dir = os.path.join(msg_dir, folder)
        if os.path.isdir(folder_dir):
            files = [f for f in os.listdir(folder_dir) if f.endswith(".bmsg")]
            total_msgs += len(files)
            for fname in files:
                content = open(os.path.join(folder_dir, fname)).read()
                if "BEGIN:BMSG" not in content or "END:BMSG" not in content:
                    errors.append(f"messages/{folder}/{fname}: invalid bMessage structure")
    if total_msgs != expected_messages:
        errors.append(f"messages: expected {expected_messages} bmsg files, got {total_msgs}")

    # Listing XMLs
    for folder in ["inbox", "sent", "draft", "deleted"]:
        xml_path = os.path.join(msg_dir, f"{folder}_listing.xml")
        if not os.path.exists(xml_path):
            errors.append(f"messages/{folder}_listing.xml: missing")

    # AT data
    for fname in ["at_phonebook.txt", "at_sms.txt"]:
        if not os.path.exists(os.path.join(output_dir, fname)):
            errors.append(f"{fname}: missing")

    return errors


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generate canned IVI data")
    parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")
    parser.add_argument("--contacts", type=int, default=50, help="Number of contacts (default: 50)")
    parser.add_argument("--messages", type=int, default=20, help="Number of SMS messages (default: 20)")
    parser.add_argument("--output-dir", default=None, help="Output directory (default: same dir as script)")
    parser.add_argument("--clean", action="store_true", help="Delete existing data before generating")
    args = parser.parse_args()

    output_dir = args.output_dir or os.path.dirname(os.path.abspath(__file__))

    if args.clean:
        for fname in ["phonebook.vcf", "ich.vcf", "och.vcf", "mch.vcf", "cch.vcf",
                       "at_phonebook.txt", "at_sms.txt"]:
            fpath = os.path.join(output_dir, fname)
            if os.path.exists(fpath):
                os.remove(fpath)
        msg_dir = os.path.join(output_dir, "messages")
        if os.path.isdir(msg_dir):
            shutil.rmtree(msg_dir)
            os.makedirs(os.path.join(msg_dir, "inbox"), exist_ok=True)
            os.makedirs(os.path.join(msg_dir, "sent"), exist_ok=True)
            os.makedirs(os.path.join(msg_dir, "draft"), exist_ok=True)
            os.makedirs(os.path.join(msg_dir, "deleted"), exist_ok=True)
        print("[*] Cleaned existing data")

    random.seed(args.seed)
    print(f"[*] Seed: {args.seed}")

    # Generate contacts
    contacts = gen_contacts(args.contacts)
    write_phonebook(contacts, output_dir)
    print(f"[+] phonebook.vcf: {len(contacts)} contacts")

    # Generate call history
    entries = gen_call_history(contacts, 20, 15, 10)
    write_call_history(entries, output_dir)
    incoming = sum(1 for e in entries if e.call_type == "RECEIVED")
    outgoing = sum(1 for e in entries if e.call_type == "DIALED")
    missed = sum(1 for e in entries if e.call_type == "MISSED")
    print(f"[+] Call history: {incoming} incoming, {outgoing} outgoing, {missed} missed")

    # Generate messages
    messages = gen_messages(contacts, SMS_BODIES, total=args.messages)
    write_messages(messages, output_dir)
    write_msg_listings(messages, output_dir)
    for folder in ["inbox", "sent", "draft", "deleted"]:
        count = sum(1 for m in messages if m.folder == folder)
        print(f"[+] messages/{folder}: {count} messages")

    # Generate AT command data
    write_at_phonebook(contacts, output_dir)
    write_at_sms(messages, output_dir)
    print(f"[+] at_phonebook.txt: {len(contacts)} entries")
    print(f"[+] at_sms.txt: {len(messages)} entries")

    # Validate
    errors = validate(output_dir, args.contacts, args.messages)
    if errors:
        print("\n[!] Validation FAILED:")
        for e in errors:
            print(f"    - {e}")
        sys.exit(1)
    else:
        print("\n[+] Validation passed — all data OK")
        total_files = (1 + 4 + len(messages) + 4 + 2)  # pb + call + msgs + xmls + at
        print(f"[+] Total: {total_files} files generated")


if __name__ == "__main__":
    main()
