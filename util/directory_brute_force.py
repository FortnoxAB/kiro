import queue
import threading
import urllib3
import urllib.parse as url_parse
import urllib.error as url_error


class BruteForce:
    def __wordlist_build(self):
        words = queue.Queue()

        with open(self.filepath) as fp:
            raw = fp.readline()
            while raw:
                word = raw.strip()
                words.put(word)
                raw = fp.readline()

        fp.close()
        return words

    def __brut_dir(self, word_queue):
        while not word_queue.empty():
            try_this = word_queue.get()
            try_list = []

            if "." not in try_this:
                try_list.append("/{}/".format(try_this))
            else:
                try_list.append("/{}".format(try_this))

            for brute in try_list:
                url = "{}{}".format(self.target, url_parse.quote(brute))

                try:
                    http = urllib3.PoolManager()
                    head = {"User-Agent": self.user_agent}
                    response = http.request("GET", headers=head, url=url)

                    if len(response.data):
                        if response.status != 404:
                            self.results.append("[{}] ==> {}".format(response.status, url))

                except (url_error.URLError, url_error.HTTPError):
                    if hasattr(url_error.HTTPError, 'code') and url_error.HTTPError.code != 404:
                        print("!!!!! [{}] ==> {}".format(url_error.HTTPError.code, url))
                    pass

    def __start(self):
        d_queue = self.__wordlist_build()
        threads = []

        for i in range(self.no_of_threads):
            t = threading.Thread(target=self.__brut_dir, args=(d_queue,))
            threads.append(t)

        for x in threads:
            x.start()

        for x in threads:
            x.join()

        self.results.sort()

        return self.results

    def __init__(self, target, no_of_threads, wordlist):
        self.target = target
        self.no_of_threads = no_of_threads
        self.filepath = wordlist
        self.user_agent = "kiro-automated-tool"
        self.results = []

    @staticmethod
    def start(target, no_of_threads=5, wordlist="./bruteforce_dir_wordlist.txt"):
        b = BruteForce(target, no_of_threads, wordlist)
        result = b.__start()
        return result
