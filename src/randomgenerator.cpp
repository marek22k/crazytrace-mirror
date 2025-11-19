// SPDX-FileCopyrightText: Copyright (C) 2024-2025 Marek Küthe <m.k@mk16.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "randomgenerator.hpp"

RandomGenerator::RandomGenerator(std::size_t max, std::size_t min) noexcept :
    _rng(std::random_device()()),
    _distribution(min, max)
{
}

std::size_t RandomGenerator::generate() noexcept
{
    return this->_distribution(this->_rng);
}
