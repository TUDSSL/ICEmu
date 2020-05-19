#include <cstdlib>
#include <fstream>
#include <iostream>

#include "json/json.h"

using namespace std;

class Config {
    private:
        string cfg_file_;
        bool good_ = false;

        bool read();
    public:
        Json::Value setting;

        Config(const string cfg_file) {
            cfg_file_ = cfg_file;
            good_ = read();
        }
        ~Config() {}

        bool good() {return good_;}
        bool bad() {return !good_;}
};

bool Config::read()
{
    ifstream ifs(cfg_file_);

    if (ifs.fail()) {
        cerr << "Could not open file: " << cfg_file_ << endl;
        return false;
    }

    Json::CharReaderBuilder builder;
    Json::CharReader *reader = builder.newCharReader();
    string errs;

    if (!parseFromStream(builder, ifs, &setting, &errs)) {
        cerr << errs << endl;
        return false;
    }
    delete reader;

    return true;
}

int main(int argc, char **argv) {
    cout << "ICEmu ARM Emulator" << endl;

    // TODO: Make actual argument parsing, don't know what the "C++" way is
    if (argc < 2) {
        cerr << "Please provide an .json config file as the first argument" << endl;
        return EXIT_FAILURE;
    }

    char *cfg_file = argv[1];
    Config cfg(cfg_file);

    if (cfg.bad()) {
        return EXIT_FAILURE;
    }

    for (const auto &m : cfg.setting["memory"]) {
        cout << m << endl;
    }
}
