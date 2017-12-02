def import_file(filename, split=False):
    with open(filename, 'r') as f:
        if split:
            return [line.strip() for line in f.readlines()]
        else:
            return f.read().strip()
