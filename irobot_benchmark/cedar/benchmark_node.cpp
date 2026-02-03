#include "rclcpp/rclcpp.hpp"
#include "std_msgs/msg/string.hpp"
#include "std_msgs/msg/float32.hpp"
#include <time.h>
#include <iostream>
#include <chrono>

clock_t start;
clock_t end;

std::chrono::time_point<std::chrono::high_resolution_clock> start_montreal, end_montreal;

std::chrono::time_point<std::chrono::high_resolution_clock> start_lyon, end_lyon;
std::vector<long double> lyon_timeStamps;

std::chrono::time_point<std::chrono::high_resolution_clock> start_hamburg, end_hamburg;
std::vector<long double> hamburg_timeStamps;

std::chrono::time_point<std::chrono::high_resolution_clock> start_osaka, end_osaka;
std::vector<long double> osaka_timeStamps;

std::chrono::time_point<std::chrono::high_resolution_clock> start_tripoli, end_tripoli;
std::vector<long double> tripoli_timeStamps;

std::chrono::time_point<std::chrono::high_resolution_clock> start_mandalay, end_mandalay;
std::vector<long double> mandalay_timeStamps;

std::chrono::time_point<std::chrono::high_resolution_clock> start_ponce, end_ponce;
std::vector<long double> ponce_timeStamps;

std::chrono::time_point<std::chrono::high_resolution_clock> start_barcelona, end_barcelona;
std::vector<long double> barcelona_timeStamps;

std::chrono::time_point<std::chrono::high_resolution_clock> start_georgetown, end_georgetown;
std::vector<long double> georgetown_timeStamps;

// Publisher Node
class montreal : public rclcpp::Node
{
public:
    montreal() : Node("montreal")
    {
        publisher1_ = this->create_publisher<std_msgs::msg::Float32>("amazon", 10);
        publisher2_ = this->create_publisher<std_msgs::msg::String>("danube", 10);
        publisher3_ = this->create_publisher<std_msgs::msg::String>("nile", 10);
        publisher4_ = this->create_publisher<std_msgs::msg::String>("ganges", 10);

        timer_ = this->create_wall_timer(
            std::chrono::seconds(1),
            std::bind(&montreal::timer_callback, this));
    }

private:
    void timer_callback()
    {
        auto message_float = std_msgs::msg::Float32();
        message_float.data = 25.22;
        start_montreal = std::chrono::high_resolution_clock::now();
        RCLCPP_INFO(this->get_logger(), "Publishing: '%ld'", start_montreal);
        publisher1_->publish(message_float);
        auto message_string = std_msgs::msg::String();
        message_string.data = "Hello, ROS2!";
        // RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", message.data.c_str());
        publisher2_->publish(message_string);
        publisher3_->publish(message_string);
        publisher4_->publish(message_string);
    }

    rclcpp::Publisher<std_msgs::msg::Float32>::SharedPtr publisher1_;
    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher2_;
    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher3_;
    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher4_;
    rclcpp::TimerBase::SharedPtr timer_;
};

class munich : public rclcpp::Node
{
public:
    munich() : Node("munich")
    {
        subscriptionA_ = this->create_subscription<std_msgs::msg::String>(
            "danube", 10,
            std::bind(&munich::topicA_callback, this, std::placeholders::_1));
        subscriptionB_ = this->create_subscription<std_msgs::msg::Float32>(
            "amazon", 10,
            std::bind(&munich::topicB_callback, this, std::placeholders::_1));

        publisher1_ = this->create_publisher<std_msgs::msg::String>("rhine", 10);
        timer_ = this->create_wall_timer(
            std::chrono::seconds(1),
            std::bind(&munich::timer_callback, this));
    }

private:
    void timer_callback()
    {
        auto message = std_msgs::msg::String();
        message.data = "Hello, ROS2!";
        // RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", message.data.c_str());
        publisher1_->publish(message);
    }

    void topicA_callback(const std_msgs::msg::String::SharedPtr msg) const
    {
        // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
        publisher1_->publish(*msg);
        // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
    }

    void topicB_callback(const std_msgs::msg::Float32::SharedPtr msg) const
    {
        // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
        // publisher1_->publish(*msg);
        // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher1_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionA_;
    rclcpp::Subscription<std_msgs::msg::Float32>::SharedPtr subscriptionB_;
    rclcpp::TimerBase::SharedPtr timer_;
};

class hamburg : public rclcpp::Node
{
public:
    hamburg() : Node("hamburg")
    {
        publisher1_ = this->create_publisher<std_msgs::msg::Float32>("parana", 10);

        // timer1_ = this->create_wall_timer(10ms, std::bind(&hamburg::publish_topic1, this));
        // Subscribers
        subscriptionA_ = this->create_subscription<std_msgs::msg::String>(
            "nile", 10, std::bind(&hamburg::topicA_callback, this, std::placeholders::_1));
        subscriptionB_ = this->create_subscription<std_msgs::msg::Float32>(
            "amazon", 10, std::bind(&hamburg::topicB_callback, this, std::placeholders::_1));
        subscriptionC_ = this->create_subscription<std_msgs::msg::String>(
            "ganges", 10, std::bind(&hamburg::topicC_callback, this, std::placeholders::_1));
        subscriptionD_ = this->create_subscription<std_msgs::msg::String>(
            "danube", 10, std::bind(&hamburg::topicD_callback, this, std::placeholders::_1));
    }

private:
    void topicA_callback(const std_msgs::msg::String::SharedPtr msg) const
    {
        // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
        // publisher1_->publish(*msg);
        // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
    }
    void topicB_callback(const std_msgs::msg::Float32::SharedPtr msg) const
    {
        start_hamburg = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(start_hamburg - start_montreal);

        RCLCPP_INFO(this->get_logger(), "Message Reached here at %llu", duration.count());

        publisher1_->publish(*msg);
    }
    void topicC_callback(const std_msgs::msg::String::SharedPtr msg) const
    {
        // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
        // publisher1_->publish(*msg);
        // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
    }

    void topicD_callback(const std_msgs::msg::String::SharedPtr msg) const
    {
        // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
        // publisher1_->publish(*msg);
        // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
    }

    rclcpp::Publisher<std_msgs::msg::Float32>::SharedPtr publisher1_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionA_;
    rclcpp::Subscription<std_msgs::msg::Float32>::SharedPtr subscriptionB_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionC_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionD_;
};

class osaka : public rclcpp::Node
{
public:
    osaka() : Node("osaka")
    {
        publisher1_ = this->create_publisher<std_msgs::msg::Float32>("salween", 10);

        //  timer_ = this->create_wall_timer(
        //       std::chrono::seconds(1),
        //       std::bind(&osaka::timer_callback, this));

        // Subscribers
        subscriptionA_ = this->create_subscription<std_msgs::msg::Float32>(
            "parana", 10, std::bind(&osaka::topicA_callback, this, std::placeholders::_1));
    }

private:
    // void timer_callback()
    // {
    //     auto message = std_msgs::msg::String();
    //     message.data = "Hello, ROS2!";
    //     // RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", message.data.c_str());
    //     publisher1_->publish(message);
    // }

    void topicA_callback(const std_msgs::msg::Float32::SharedPtr msg) const
    {
        start_osaka = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(start_osaka - start_montreal);

        RCLCPP_INFO(this->get_logger(), "Message Reached here at %llu", duration.count());
        publisher1_->publish(*msg);
    }

    rclcpp::Publisher<std_msgs::msg::Float32>::SharedPtr publisher1_;
    rclcpp::Subscription<std_msgs::msg::Float32>::SharedPtr subscriptionA_;
};

class mandalay : public rclcpp::Node
{
public:
    mandalay() : Node("mandalay")
    {
        publisher1_ = this->create_publisher<std_msgs::msg::Float32>("missouri", 10);

        // timer_ = this->create_wall_timer(
        //     std::chrono::seconds(1),
        //     std::bind(&mandalay::timer_callback, this));

        // Subscribers
        subscriptionA_ = this->create_subscription<std_msgs::msg::String>(
            "rhine", 10, std::bind(&mandalay::topicA_callback, this, std::placeholders::_1));

        subscriptionB_ = this->create_subscription<std_msgs::msg::Float32>(
            "salween", 10, std::bind(&mandalay::topicB_callback, this, std::placeholders::_1));
    }

private:
    // void timer_callback()
    // {
    //     auto message = std_msgs::msg::String();
    //     message.data = "Hello, ROS2!";
    //     // RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", message.data.c_str());
    //     publisher1_->publish(message);
    //     publisher3_->publish(message);
    // }

    void topicA_callback(const std_msgs::msg::String::SharedPtr msg) const
    {
        // // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
        // publisher1_->publish(*msg);
        // publisher3_->publish(*msg);
        // // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
    }

    void topicB_callback(const std_msgs::msg::Float32::SharedPtr msg) const
    {
        start_mandalay = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(start_mandalay - start_montreal);

        RCLCPP_INFO(this->get_logger(), "Message Reached here at %llu", duration.count());

        publisher1_->publish(*msg);
    }

    rclcpp::Publisher<std_msgs::msg::Float32>::SharedPtr publisher1_;

    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionA_;
    rclcpp::Subscription<std_msgs::msg::Float32>::SharedPtr subscriptionB_;

    rclcpp::TimerBase::SharedPtr timer_;
};

class ponce : public rclcpp::Node
{
public:
    ponce() : Node("ponce")
    {
        publisher1_ = this->create_publisher<std_msgs::msg::String>("congo", 10);
        publisher2_ = this->create_publisher<std_msgs::msg::Float32>("mekong", 10);

        timer_ = this->create_wall_timer(
            std::chrono::seconds(1),
            std::bind(&ponce::timer_callback, this));

        // Subscribers

        subscriptionA_ = this->create_subscription<std_msgs::msg::Float32>(
            "missouri", 10, std::bind(&ponce::topicA_callback, this, std::placeholders::_1));
        subscriptionB_ = this->create_subscription<std_msgs::msg::String>(
            "rhine", 10, std::bind(&ponce::topicB_callback, this, std::placeholders::_1));
    }

private:
    void timer_callback()
    {
        auto message = std_msgs::msg::String();
        message.data = "Hello, ROS2!";
        // RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", message.data.c_str());
        publisher1_->publish(message);
    }

    void topicA_callback(const std_msgs::msg::Float32::SharedPtr msg) const
    {
        start_ponce = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(start_ponce - start_montreal);
        RCLCPP_INFO(this->get_logger(), "Message Reached here at %llu", duration.count());

        publisher2_->publish(*msg);
    }

    void topicB_callback(const std_msgs::msg::String::SharedPtr msg) const
    {
        // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
        publisher1_->publish(*msg);
        // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher1_;
    rclcpp::Publisher<std_msgs::msg::Float32>::SharedPtr publisher2_;

    rclcpp::Subscription<std_msgs::msg::Float32>::SharedPtr subscriptionA_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionB_;

    rclcpp::TimerBase::SharedPtr timer_;
};

class geneva : public rclcpp::Node
{
public:
    geneva() : Node("geneva")
    {
        publisher1_ = this->create_publisher<std_msgs::msg::String>("arkansas", 10);

        timer_ = this->create_wall_timer(
            std::chrono::seconds(1),
            std::bind(&geneva::timer_callback, this));

        // Subscribers
        subscriptionA_ = this->create_subscription<std_msgs::msg::String>(
            "rhine", 10, std::bind(&geneva::topicA_callback, this, std::placeholders::_1));
        subscriptionB_ = this->create_subscription<std_msgs::msg::String>(
            "congo", 10, std::bind(&geneva::topicB_callback, this, std::placeholders::_1));
    }

private:
    void timer_callback()
    {
        auto message = std_msgs::msg::String();
        message.data = "Hello, ROS2!";
        // RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", message.data.c_str());
        publisher1_->publish(message);
    }

    void topicA_callback(const std_msgs::msg::String::SharedPtr msg) const
    {
        // //RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
        publisher1_->publish(*msg);
        // //RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
    }

    void topicB_callback(const std_msgs::msg::String::SharedPtr msg) const
    {
        // //RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
        publisher1_->publish(*msg);
        // //RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher1_;

    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionA_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionB_;

    rclcpp::TimerBase::SharedPtr timer_;
};

class barcelona : public rclcpp::Node
{
public:
    barcelona() : Node("barcelona")
    {
        publisher1_ = this->create_publisher<std_msgs::msg::Float32>("lena", 10);

        //  timer_ = this->create_wall_timer(
        //       std::chrono::seconds(1),
        //       std::bind(&barcelona::timer_callback, this));

        // Subscribers
        subscriptionA_ = this->create_subscription<std_msgs::msg::Float32>(
            "mekong", 10, std::bind(&barcelona::topicA_callback, this, std::placeholders::_1));
    }

private:
    // void timer_callback()
    // {
    //     auto message = std_msgs::msg::String();
    //     message.data = "Hello, ROS2!";
    //     //RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", message.data.c_str());
    //     publisher1_->publish(message);
    // }

    void topicA_callback(const std_msgs::msg::Float32::SharedPtr msg) const
    {
        start_barcelona = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(start_barcelona - start_montreal);

        RCLCPP_INFO(this->get_logger(), "Message Reached here at %llu", duration.count());

        publisher1_->publish(*msg);
    }

    rclcpp::Publisher<std_msgs::msg::Float32>::SharedPtr publisher1_;

    rclcpp::Subscription<std_msgs::msg::Float32>::SharedPtr subscriptionA_;

    rclcpp::TimerBase::SharedPtr timer_;
};

class georgetown : public rclcpp::Node
{
public:
    georgetown() : Node("georgetown")
    {

        // Subscribers

        subscriptionA_ = this->create_subscription<std_msgs::msg::Float32>(
            "lena", 10, std::bind(&georgetown::topicA_callback, this, std::placeholders::_1));
    }

private:
    void topicA_callback(const std_msgs::msg::Float32::SharedPtr msg) const
    {
        start_georgetown = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(start_georgetown - start_montreal);

        RCLCPP_INFO(this->get_logger(), "Message Reached here at %llu", duration.count());
    }

    rclcpp::Subscription<std_msgs::msg::Float32>::SharedPtr subscriptionA_;

    rclcpp::TimerBase::SharedPtr timer_;
};


extern "C" {
__attribute__((weak))
void protect_trusted_libraries_with_pkey(void);
}


int main(int argc, char **argv)
{

          if (protect_trusted_libraries_with_pkey) {
        printf("ehllo");
        protect_trusted_libraries_with_pkey();
    }
    protect_trusted_libraries_with_pkey();


 if (argc < 2)
    {
        std::cerr << "Usage: ./app <start_time_in_us>" << std::endl;
        return 1;
    }

    // Convert the argument to a long long (microseconds)
    long long start_time_us = std::atoll(argv[1]);

    // Get the current time at the start of main() in microseconds
    auto main_time = std::chrono::high_resolution_clock::now();
    auto main_time_us =
        std::chrono::time_point_cast<std::chrono::microseconds>(
            main_time).time_since_epoch().count();

    // Calculate the difference
    long long duration_us = main_time_us - start_time_us;

    std::cout << "Time elapsed from execve to main(): "
              << duration_us << " microseconds" << std::endl;





    // Rest of the application code

    rclcpp::init(argc, argv);

    // Create a vector to hold all the node instances
    std::vector<std::shared_ptr<rclcpp::Node>> nodes;

    // Add instances of each node to the vector
    nodes.push_back(std::make_shared<montreal>());
    nodes.push_back(std::make_shared<munich>());
    nodes.push_back(std::make_shared<hamburg>());
    nodes.push_back(std::make_shared<osaka>());
    nodes.push_back(std::make_shared<mandalay>());
    nodes.push_back(std::make_shared<ponce>());
    nodes.push_back(std::make_shared<geneva>());
    nodes.push_back(std::make_shared<barcelona>());
    nodes.push_back(std::make_shared<georgetown>());

    // Create an executor
    rclcpp::executors::SingleThreadedExecutor executor;

    // Add each node to the executor
    for (auto &node : nodes)
    {
        executor.add_node(node);
    }

    // Spin the executor
    executor.spin();

    // Shutdown ROS
    rclcpp::shutdown();
    return 0;
}
