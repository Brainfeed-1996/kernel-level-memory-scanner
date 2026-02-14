#ifndef NEURAL_NETWORK_H
#define NEURAL_NETWORK_H

#include <iostream>
#include <string>
#include <vector>
#include <cmath>

namespace KernelScanner {

class NeuralNetworkAnomalyDetection {
public:
    struct NetworkConfig {
        std::vector<int> layers;
        std::vector<std::vector<double>> weights;
        std::vector<std::vector<double>> biases;
        double learning_rate;
    };
    
    struct AnomalyScore {
        double score;
        std::string classification;
        std::vector<double> feature_importance;
    };
    
    NeuralNetworkAnomalyDetection();
    void initialize_network(const NetworkConfig& config);
    AnomalyScore predict_anomaly(const std::vector<double>& features);
    void train(const std::vector<std::vector<double>>& training_data);
    void print_network_architecture();

private:
    NetworkConfig config;
    std::vector<std::vector<double>> hidden_activations;
};

} // namespace KernelScanner

#endif
