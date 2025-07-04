/*
 * SPDX-FileCopyrightText: 2024 Marek Küthe <m.k@mk16.de>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef RANDOMGENERATOR_HPP
#define RANDOMGENERATOR_HPP

#include <random>
#include <cstddef>

class RandomGenerator
{
    public:
        explicit RandomGenerator(std::size_t max, std::size_t min = 0) noexcept;
        [[nodiscard]] std::size_t generate() noexcept;

    private:
        std::default_random_engine _rng;
        std::uniform_int_distribution<std::size_t> _distribution;
};

#endif
